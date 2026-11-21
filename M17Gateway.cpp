/*
*   Copyright (C) 2016,2017,2018,2020,2021,2024,2025 by Jonathan Naylor G4KLX
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program; if not, write to the Free Software
*   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "M17Gateway.h"
#include "RptNetwork.h"
#include "Reflectors.h"
#include "StopWatch.h"
#include "M17Utils.h"
#include "Version.h"
#include "Thread.h"
#include "M17LSF.h"
#include "Timer.h"
#include "Voice.h"
#include "Utils.h"
#include "Echo.h"
#include "Log.h"
#include "MQTTConnection.h"
#include "GitVersion.h"

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
const char* DEFAULT_INI_FILE = "M17Gateway.ini";
#else
const char* DEFAULT_INI_FILE = "/etc/M17Gateway.ini";
#endif

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <ctime>
#include <cstring>

static bool m_killed = false;
static int  m_signal = 0;

// The running gateway, for the MQTT command callback, which has no context of its own
static CM17Gateway* m_gateway = nullptr;

// Defined in Log.cpp, so log lines can also be published
extern CMQTTConnection* m_mqtt;

// Probing a reflector with a packet to PARROT, to find whether it uses the legacy protocol
const unsigned int PROBE_TIMEOUT = 1500U;	// Milliseconds to wait for each reply, about ten times a normal reply
const unsigned int PROBE_TRIES   = 3U;
const char*        PROBE_MARKER  = "M17Gateway PARROT probe ";

#if !defined(_WIN32) && !defined(_WIN64)
static void sigHandler(int signum)
{
	m_killed = true;
	m_signal = signum;
}
#endif

int main(int argc, char** argv)
{
	const char* iniFile = DEFAULT_INI_FILE;
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "M17Gateway version %s git #%.7s\n", VERSION, gitversion);
				return 0;
			} else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: M17Gateway [-v|--version] [filename]\n");
				return 1;
			} else {
				iniFile = argv[currentArg];
			}
		}
	}

#if !defined(_WIN32) && !defined(_WIN64)
	::signal(SIGINT,  sigHandler);
	::signal(SIGTERM, sigHandler);
	::signal(SIGHUP,  sigHandler);
#endif

	int ret = 0;

	do {
		m_signal = 0;

		CM17Gateway* gateway = new CM17Gateway(std::string(iniFile));
		ret = gateway->run();

		delete gateway;

		switch (m_signal) {
			case 0:
				break;
			case 2:
				::LogInfo("M17Gateway-%s exited on receipt of SIGINT", VERSION);
				break;
			case 15:
				::LogInfo("M17Gateway-%s exited on receipt of SIGTERM", VERSION);
				break;
			case 1:
				::LogInfo("M17Gateway-%s is restarting on receipt of SIGHUP", VERSION);
				break;
			default:
				::LogInfo("M17Gateway-%s exited on receipt of an unknown signal", VERSION);
				break;
		}
	} while (m_signal == 1);

	::LogFinalise();

	return ret;
}

CM17Gateway::CM17Gateway(const std::string& file) :
m_conf(file),
m_status(M17_STATUS::NOTLINKED),
m_oldStatus(M17_STATUS::NOTLINKED),
m_network(nullptr),
m_reflector(),
m_addrLen(0U),
m_addr(),
m_module(' '),
m_writer(nullptr),
m_gps(nullptr),
m_legacy(false),
m_probe(nullptr),
m_probeLength(0U),
m_probeTries(0U),
m_probeTimer(1000U, 0U, PROBE_TIMEOUT)
{
	CUDPSocket::startup();

	m_probe = new unsigned char[M17_PACKET_NETWORK_MAX_LENGTH];

	::srand((unsigned int)::time(nullptr));
}

CM17Gateway::~CM17Gateway()
{
	delete[] m_probe;

	CUDPSocket::shutdown();
}

// Legacy reflectors (urfd, and mrefd before 1.0.0) only forward streams addressed to the reflector
// and module, and don't support packet mode. A reflector using the current protocol forwards traffic
// to its real destination, which is passed on unchanged. A reflector is treated as current until it
// fails to answer a packet sent to PARROT, which no legacy reflector supports.
bool CM17Gateway::isLegacyReflector() const
{
	return m_legacy;
}

void CM17Gateway::startProbe()
{
	m_legacy      = false;
	m_probeTries  = 0U;
	m_probeLength = 0U;

	// An M17P packet from this gateway to PARROT, raw data with a random tag so the reply can be recognised
	unsigned char* p = m_probe;
	::memcpy(p, "M17P", 4U);
	p += 4U;

	::memset(p, 0x00U, M17_LSF_LENGTH_BYTES);
	CM17Utils::encodeCallsign("PARROT", p + 0U);
	CM17Utils::encodeCallsign(linkCallsign(), p + 6U);
	// TYPE is all zeros for packet mode, and META is unused
	CM17Utils::addCRC16(p, M17_LSF_LENGTH_BYTES - M17_CRC_LENGTH_BYTES);
	p += M17_LSF_LENGTH_BYTES;

	unsigned char* payload = p;
	*p++ = M17_PACKET_PROTOCOL_RAW;
	::memcpy(p, PROBE_MARKER, ::strlen(PROBE_MARKER));
	p += ::strlen(PROBE_MARKER);
	for (unsigned int i = 0U; i < 4U; i++)
		*p++ = ::rand() & 0xFFU;
	CM17Utils::addCRC16(payload, p - payload);
	p += M17_CRC_LENGTH_BYTES;

	m_probeLength = p - m_probe;

	sendProbe();
}

void CM17Gateway::sendProbe()
{
	m_probeTries++;
	LogDebug("Sending PARROT probe %u to %s", m_probeTries, m_reflector.c_str());

	m_network->writePacket(m_probe, m_probeLength);
	m_probeTimer.start();
}

void CM17Gateway::clockProbe(unsigned int ms)
{
	m_probeTimer.clock(ms);
	if (!m_probeTimer.isRunning() || !m_probeTimer.hasExpired())
		return;

	if (m_status != M17_STATUS::LINKED) {
		// The link went away, a new probe is sent when it comes back
		m_probeTimer.stop();
	} else if (m_probeTries < PROBE_TRIES) {
		sendProbe();
	} else {
		m_probeTimer.stop();
		m_legacy = true;
		LogMessage("%s did not answer a packet to PARROT, treating it as a legacy reflector", m_reflector.c_str());
	}
}

// Is this the reflector's PARROT reply to the probe? The reflector may readdress it, so only the data is compared
bool CM17Gateway::isProbeReply(const unsigned char* packet, unsigned int length)
{
	assert(packet != nullptr);

	if (m_probeLength == 0U || length != m_probeLength)
		return false;

	unsigned int offset = 4U + M17_LSF_LENGTH_BYTES;
	if (::memcmp(packet + offset, m_probe + offset, m_probeLength - offset) != 0)
		return false;

	if (m_probeTimer.isRunning() || m_legacy)
		LogMessage("%s answered a packet to PARROT, it uses the current protocol", m_reflector.c_str());

	m_probeTimer.stop();
	m_legacy = false;

	return true;
}

// The decoded broadcast address is padded with spaces, which looks odd in the log
// The callsign this gateway links with: the callsign and the suffix in the last place
std::string CM17Gateway::linkCallsign() const
{
	std::string callsign = m_conf.getCallsign();
	callsign.resize(M17_CALLSIGN_LENGTH - 1U, ' ');
	callsign += m_conf.getSuffix().substr(0U, 1U);
	return callsign;
}

std::string CM17Gateway::trim(const std::string& callsign)
{
	return callsign.substr(0U, callsign.find_last_not_of(' ') + 1U);
}

bool CM17Gateway::isBroadcast(const std::string& dst)
{
	std::string trimmed = trim(dst);

	return trimmed.empty() || trimmed == "ALL" || trimmed == "#ALL";
}

void CM17Gateway::writeStream(unsigned char* buffer, const std::string& src, const std::string& dst)
{
	assert(buffer != nullptr);

	if (isLegacyReflector()) {
		if (isBroadcast(dst)) {
			CM17Utils::encodeCallsign(m_reflector, buffer + 6U);
		} else {
			// Only on the first frame, the last frame of a stream can also have a zero frame number
			uint16_t fn = (buffer[34U] << 8) + (buffer[35U] << 0);
			if (fn == 0U)
				LogMessage("Voice from %s to %s, %s only accepts broadcast traffic, so it will probably be dropped", src.c_str(), dst.c_str(), m_reflector.c_str());
		}
	}

	// MMDVMHost sends a zero CRC, and the destination may have changed above. Reflectors pass the CRC on
	// to their other clients, some of which check it, so it has to be right.
	CM17Utils::addCRC16(buffer, M17_NETWORK_FRAME_LENGTH - M17_CRC_LENGTH_BYTES);

	m_network->write(buffer);
}

int CM17Gateway::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "M17Gateway: cannot read the .ini file\n");
		return 1;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	bool m_daemon = m_conf.getDaemon();
	if (m_daemon) {
		// Create new process
		pid_t pid = ::fork();
		if (pid == -1) {
			::fprintf(stderr, "Couldn't fork() , exiting\n");
			return 1;
		} else if (pid != 0) {
			exit(EXIT_SUCCESS);
		}

		// Create new session and process group
		if (::setsid() == -1) {
			::fprintf(stderr, "Couldn't setsid(), exiting\n");
			return 1;
		}

		// Set the working directory to the root directory
		if (::chdir("/") == -1) {
			::fprintf(stderr, "Couldn't cd /, exiting\n");
			return 1;
		}

		// If we are currently root...
		if (getuid() == 0) {
			struct passwd* user = ::getpwnam("mmdvm");
			if (user == nullptr) {
				::fprintf(stderr, "Could not get the mmdvm user, exiting\n");
				return 1;
			}

			uid_t mmdvm_uid = user->pw_uid;
			gid_t mmdvm_gid = user->pw_gid;

			// Set user and group ID's to mmdvm:mmdvm
			if (setgid(mmdvm_gid) != 0) {
				::fprintf(stderr, "Could not set mmdvm GID, exiting\n");
				return 1;
			}

			if (setuid(mmdvm_uid) != 0) {
				::fprintf(stderr, "Could not set mmdvm UID, exiting\n");
				return 1;
			}

			// Double check it worked (AKA Paranoia)
			if (setuid(0) != -1) {
				::fprintf(stderr, "It's possible to regain root - something is wrong!, exiting\n");
				return 1;
			}
		}
	}
#endif

#if !defined(_WIN32) && !defined(_WIN64)
        ret = ::LogInitialise(m_daemon, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate(), m_conf.getLogMQTTLevel());
#else
        ret = ::LogInitialise(false, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate(), m_conf.getLogMQTTLevel());
#endif
	if (!ret) {
		::fprintf(stderr, "M17Gateway: unable to open the log file\n");
		return -1;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	if (m_daemon) {
		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);
	}
#endif

	// MQTT, as in G4KLX's gateway programs, in addition to the log file and the UDP remote commands:
	// status and link messages on <Name>/json, log lines on <Name>/log, and the remote commands on
	// <Name>/command, answered on <Name>/response. The connection retries in the background if the
	// broker isn't there.
	m_gateway = this;
	std::vector<std::pair<std::string, void (*)(const unsigned char*, unsigned int)>> subscriptions;
	if (m_conf.getRemoteCommandsEnabled())
		subscriptions.push_back(std::make_pair("command", CM17Gateway::onCommand));

	m_mqtt = new CMQTTConnection(m_conf.getMQTTAddress(), m_conf.getMQTTPort(), m_conf.getMQTTName(), m_conf.getMQTTAuthEnabled(), m_conf.getMQTTUsername(), m_conf.getMQTTPassword(), subscriptions, m_conf.getMQTTKeepalive());
	ret = m_mqtt->open();
	if (!ret) {
		delete m_mqtt;
		m_mqtt = nullptr;
		LogWarning("Unable to start MQTT, continuing without it");
	}

	createGPS();

	CRptNetwork* localNetwork = new CRptNetwork(m_conf.getMyPort(), m_conf.getRptAddress(), m_conf.getRptPort(), m_conf.getDebug());
	ret = localNetwork->open();
	if (!ret)
		return 1;

	m_network = new CM17Network(m_conf.getCallsign(), m_conf.getSuffix(), m_conf.getNetworkLocalPort(), m_conf.getNetworkDebug());

	CUDPSocket* remoteSocket = nullptr;
	if (m_conf.getRemoteCommandsEnabled()) {
		remoteSocket = new CUDPSocket(m_conf.getRemoteCommandsPort());
		ret = remoteSocket->open();
		if (!ret) {
			delete remoteSocket;
			remoteSocket = nullptr;
		}
	}

	CReflectors reflectors(m_conf.getNetworkHosts1(), m_conf.getNetworkHosts2(), m_conf.getNetworkReloadTime());
	reflectors.load();

	bool triggerVoice = false;
	CVoice* voice = nullptr;
	if (m_conf.getVoiceEnabled()) {
		voice = new CVoice(m_conf.getVoiceDirectory(), m_conf.getVoiceLanguage(), m_conf.getCallsign());
		bool ok = voice->open();
		if (!ok) {
			delete voice;
			voice = nullptr;
		}
	}

	CEcho echo(240U);

	CTimer hangTimer(1000U, m_conf.getNetworkHangTime());

	// A packet sent to ECHO is returned after a short delay, so the radio has time to return to receive
	unsigned char* echoPacket = new unsigned char[M17_PACKET_NETWORK_MAX_LENGTH];
	unsigned int echoPacketLength = 0U;
	CTimer echoPacketTimer(1000U, 1U);

	CStopWatch stopWatch;
	stopWatch.start();

	LogMessage("M17Gateway-%s is starting", VERSION);
	LogMessage("Built %s %s (GitID #%.7s)", __TIME__, __DATE__, gitversion);
	writeJSONStatus("M17Gateway is starting");

	std::string startupReflector = m_conf.getNetworkStartup();
	bool revert = m_conf.getNetworkRevert();

	if (voice != nullptr)
		voice->unlinked();

	if (!startupReflector.empty()) {
		CM17Reflector* refl = reflectors.find(startupReflector);
		if (refl != nullptr) {
			char module = startupReflector.at(M17_CALLSIGN_LENGTH - 1U);
			if (module >= 'A' && module <= 'Z') {
				m_reflector = startupReflector;
				m_addr      = refl->m_addr;
				m_addrLen   = refl->m_addrLen;
				m_module    = module;

				LogMessage("Linking at startup to %s", m_reflector.c_str());

				m_status = m_oldStatus = M17_STATUS::LINKING;
				m_network->link(m_reflector, m_addr, m_addrLen, m_module);
				writeJSONLink("linking", "startup");

				if (voice != nullptr)
					voice->linkedTo(m_reflector);
			}
		} else {
			startupReflector.clear();
		}
	}

	// The link message is retained, so say so when there is no startup reflector rather than leave an old one standing
	if (m_status == M17_STATUS::NOTLINKED)
		writeJSONLink("unlinked", "startup");

	if (voice != nullptr)
		voice->start();

	// Remote commands, over UDP or MQTT, are handled the same way and return a reply, or nothing
	auto processCommand = [&](std::string command, const std::string& via) -> std::string {
		// Tools such as netcat add a line ending
		command.erase(command.find_last_not_of(" \t\r\n") + 1U);

		if (command.compare(0U, 9U, "Reflector") == 0) {
			std::string reflector = (command.length() > 10U) ? command.substr(10U) : "";
			std::replace(reflector.begin(), reflector.end(), '_', ' ');
			reflector.resize(M17_CALLSIGN_LENGTH, ' ');

			if (reflector != m_reflector) {
				if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING) {
					LogMessage("Unlinked from reflector %s by remote command%s", m_reflector.c_str(), via.c_str());

					m_network->unlink();

					hangTimer.stop();
				}

				CM17Reflector* refl = reflectors.find(reflector);
				if (refl != nullptr) {
					char module = reflector.at(M17_CALLSIGN_LENGTH - 1U);
					if (module >= 'A' && module <= 'Z') {
						m_reflector = reflector;
						m_addr      = refl->m_addr;
						m_addrLen   = refl->m_addrLen;
						m_module    = module;

						// Link to the new reflector
						LogMessage("Switched to reflector %s by remote command%s", m_reflector.c_str(), via.c_str());

						m_status = m_oldStatus = M17_STATUS::LINKING;
						m_network->link(m_reflector, m_addr, m_addrLen, m_module);
						writeJSONLink("linking", "remote");

						if (voice != nullptr) {
							voice->linkedTo(m_reflector);
							voice->start();
						}

						hangTimer.start();
					} else {
						// Not a module: the old link is gone, say so.
						LogWarning("Invalid module in %s requested by remote command%s", reflector.c_str(), via.c_str());

						m_reflector.clear();
						if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING) {
							m_status = m_oldStatus = M17_STATUS::UNLINKING;
							writeJSONLink("unlinked", "remote");
						}

						if (voice != nullptr) {
							voice->unlinked();
							voice->start();
						}
					}
				} else {
					m_reflector.clear();
					if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING) {
						m_status = m_oldStatus = M17_STATUS::UNLINKING;
						writeJSONLink("unlinked", "remote");

						if (voice != nullptr) {
							voice->unlinked();
							voice->start();
						}
					}

					hangTimer.stop();
				}
			}

			return "";
		} else if (command.compare(0U, 6U, "status") == 0) {
			return std::string("m17:") + ((m_network == nullptr) ? "n/a" : ((m_network->getStatus() == M17NET_STATUS::LINKED) ? "conn" : "disc"));
		} else if (command.compare(0U, 4U, "host") == 0) {
			std::string ref(m_reflector);
			std::replace(ref.begin(), ref.end(), ' ', '_');
			return std::string("m17:\"") + (((m_network == nullptr) || (ref.length() == 0)) ? "NONE" : ref) + "\"";
		} else {
			CUtils::dump("Invalid remote command received", (const unsigned char*)command.c_str(), (unsigned int)command.length());
			return "";
		}
	};

	unsigned int n = 0U;

	while (!m_killed) {
		M17NET_STATUS netStatus = m_network->getStatus();

		switch (m_status) {
		case M17_STATUS::LINKING:
			switch (netStatus) {
			case M17NET_STATUS::LINKING:
				// Nothing to do
				break;
			case M17NET_STATUS::LINKED:
				m_status = m_oldStatus = M17_STATUS::LINKED;
				LogMessage("Linked to %s", m_reflector.c_str());
				writeJSONLink("linking", "established");
				startProbe();
				break;
			case M17NET_STATUS::REJECTED:
				m_status = m_oldStatus = M17_STATUS::NOTLINKED;
				LogMessage("Linking rejected by %s", m_reflector.c_str());
				writeJSONLink("failed", "rejected");
				if (voice != nullptr) {
					voice->unlinked();
					voice->start();
				}
				break;
			default:
				LogMessage("Linking failed with %s, trying again", m_reflector.c_str());
				writeJSONLink("failed", "timer");
				m_network->link(m_reflector, m_addr, m_addrLen, m_module);
				break;
			}
			break;

		case M17_STATUS::LINKED:
			switch (netStatus) {
			case M17NET_STATUS::LINKED:
				// Nothing to do
				break;
			case M17NET_STATUS::FAILED:
				LogMessage("Relinking to reflector %s", m_reflector.c_str());
				writeJSONLink("relinking", "");
				m_network->link(m_reflector, m_addr, m_addrLen, m_module);
				m_status = M17_STATUS::LINKING;
				break;
			default:
				m_status = m_oldStatus = M17_STATUS::NOTLINKED;
				LogMessage("Link failed with %s", m_reflector.c_str());
				// Disconnected by the reflector, and not retrying
				writeJSONLink("failed", "");
				if (voice != nullptr) {
					voice->unlinked();
					voice->start();
				}
				break;
			}
			break;

		case M17_STATUS::UNLINKING:
			switch (netStatus) {
			case M17NET_STATUS::UNLINKING:
				// Nothing to do
				break;
			default:
				m_status = m_oldStatus = M17_STATUS::NOTLINKED;
				LogMessage("Unlinked from %s", m_reflector.c_str());
				break;
			}
			break;

		default:	// M17_STATUS::NOTLINKED or M17_STATUS::ECHO
			break;
		}

		unsigned char buffer[100U];

		if (m_status == M17_STATUS::LINKED) {
			// From the reflector to the MMDVM
			bool ret = m_network->read(buffer);
			if (ret) {
				CM17LSF lsf;
				lsf.setNetwork(buffer + 6U);

				if (n > 40U) {
					// Change the type to show that it's callsign data
					lsf.setEncryptionType(M17_ENCRYPTION_TYPE_NONE);
					lsf.setEncryptionSubType(M17_ENCRYPTION_SUB_TYPE_CALLSIGNS);

					// Copy the encoded source and the reflector into the META field
					unsigned char meta[M17_META_LENGTH_BYTES];
					::memset(meta, 0x00U, M17_META_LENGTH_BYTES);
					::memcpy(meta + 0U, buffer + 12U, 6U);
					CM17Utils::encodeCallsign(m_reflector, meta + 6U);
					lsf.setMeta(meta);

					if (n > 45U)
						n = 0U;
				}

				n++;

				// Replace the destination callsign with the broadcast callsign
				lsf.setDest("ALL");
				lsf.getNetwork(buffer + 6U);

				localNetwork->write(buffer);

				uint16_t fn = (buffer[34U] << 8) + (buffer[35U] << 0);
				if ((fn & 0x8000U) == 0x8000U)
					n = 0U;

				hangTimer.start();
			}
		} else if (m_status == M17_STATUS::ECHO) {
			// From the echo unit to the MMDVM
			ECHO_STATE est = echo.read(buffer);
			switch (est) {
				case ECHO_STATE::DATA:
					if (n > 40U) {
						CM17LSF lsf;
						lsf.setNetwork(buffer + 6U);

						// Change the type to show that it's callsign data
						lsf.setEncryptionType(M17_ENCRYPTION_TYPE_NONE);
						lsf.setEncryptionSubType(M17_ENCRYPTION_SUB_TYPE_CALLSIGNS);

						// Copy the encoded source into the META field
						unsigned char meta[M17_META_LENGTH_BYTES];
						::memset(meta, 0x00U, M17_META_LENGTH_BYTES);
						::memcpy(meta + 0U, buffer + 12U, 6U);
						lsf.setMeta(meta);

						lsf.getNetwork(buffer + 6U);

						if (n > 45U)
							n = 0U;
					}

					n++;

					localNetwork->write(buffer);

					hangTimer.start();
					break;

				case ECHO_STATE::END:
					// End of the message, restore the original status
					m_status = m_oldStatus;
					n = 0U;
					break;

				default:
					break;
			}
		}

		// From the MMDVM to the reflector or control data
		bool ret = localNetwork->read(buffer);
		if (ret) {
			CM17LSF lsf;
			lsf.setNetwork(buffer + 6U);

			std::string src = lsf.getSource();
			std::string dst = lsf.getDest();

			if (m_gps != nullptr)
				m_gps->process(lsf);

			if (dst == "ECHO") {
				if (m_status != M17_STATUS::ECHO) {
					m_oldStatus = m_status;
					echo.clear();
				}

				echo.write(buffer);
				m_status = M17_STATUS::ECHO;
				hangTimer.start();

				uint16_t fn = (buffer[34U] << 8) + (buffer[35U] << 0);
				if ((fn & 0x8000U) == 0x8000U)
					echo.end();
			} else if (dst == "INFO") {
				hangTimer.start();
				triggerVoice = true;
			} else if (dst == "UNLINK") {
				if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING) {
					LogMessage("Unlinking from reflector %s triggered by %s", m_reflector.c_str(), src.c_str());

					m_status = m_oldStatus = M17_STATUS::UNLINKING;
					m_network->unlink();
					writeJSONLink("unlinked", "user");

					if (voice != nullptr)
						voice->unlinked();
				}

				triggerVoice = true;
				hangTimer.stop();
			} else if (dst.size() == M17_CALLSIGN_LENGTH) {
				std::string reflector = dst;
				char module = reflector.at(M17_CALLSIGN_LENGTH - 1U);

				if (reflector != m_reflector && module >= 'A' && module <= 'Z') {
					if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING) {
						LogMessage("Unlinking from reflector %s triggered by %s", m_reflector.c_str(), src.c_str());

						m_network->unlink();
					}

					triggerVoice = true;

					CM17Reflector* refl = reflectors.find(reflector);
					if (refl != nullptr) {
						m_reflector = reflector;
						m_addr      = refl->m_addr;
						m_addrLen   = refl->m_addrLen;
						m_module    = module;

						// Link to the new reflector
						LogMessage("Linking to reflector %s triggered by %s", m_reflector.c_str(), src.c_str());

						m_status = m_oldStatus = M17_STATUS::LINKING;
						m_network->link(m_reflector, m_addr, m_addrLen, m_module);
						writeJSONLink("linking", "user");

						if (voice != nullptr)
							voice->linkedTo(m_reflector);

						hangTimer.start();
					} else {
						if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING) {
							m_status = m_oldStatus = M17_STATUS::UNLINKING;
							writeJSONLink("unlinked", "user");
						}

						if (voice != nullptr)
							voice->unlinked();

						hangTimer.stop();
					}
				} else {
					if (m_status == M17_STATUS::LINKED) {
						writeStream(buffer, src, dst);
						hangTimer.start();
					}
				}
			} else {
				if (m_status == M17_STATUS::LINKED) {
					writeStream(buffer, src, dst);
					hangTimer.start();
				}
			}
		}

		// Packets from the MMDVM to the reflector, or to the echo
		unsigned char packet[M17_PACKET_NETWORK_MAX_LENGTH];
		unsigned int packetLength = localNetwork->readPacket(packet);
		if (packetLength > 0U) {
			CM17LSF lsf;
			lsf.setNetwork(packet + 4U);

			// Only used for logging and to compare, the packet itself is unchanged
			std::string src = trim(lsf.getSource());
			std::string dst = trim(lsf.getDest());

			if (dst == "ECHO") {
				LogMessage("Packet from %s to ECHO, returning it", src.c_str());

				::memcpy(echoPacket, packet, packetLength);
				echoPacketLength = packetLength;
				echoPacketTimer.start();
				hangTimer.start();
			} else if (m_status == M17_STATUS::LINKED && isLegacyReflector()) {
				LogMessage("Packet from %s to %s dropped, %s doesn't support packet mode", src.c_str(), dst.c_str(), m_reflector.c_str());
			} else if (m_status == M17_STATUS::LINKED) {
				LogMessage("Packet from %s to %s, sending it to %s", src.c_str(), dst.c_str(), m_reflector.c_str());

				// The destination is left alone, the reflector handles it and it's covered by the CRC
				m_network->writePacket(packet, packetLength);
				hangTimer.start();
			} else {
				LogMessage("Packet from %s to %s dropped, not linked to a reflector", src.c_str(), dst.c_str());
			}
		}

		// Packets from the reflector to the MMDVM
		if (m_status == M17_STATUS::LINKED) {
			packetLength = m_network->readPacket(packet);
			if (packetLength > 0U && !isProbeReply(packet, packetLength)) {
				CM17LSF lsf;
				lsf.setNetwork(packet + 4U);

				LogMessage("Packet from %s to %s received from %s", trim(lsf.getSource()).c_str(), trim(lsf.getDest()).c_str(), m_reflector.c_str());

				// Mark it as transmitted from the network, as m17-gateway does, so receivers can tell it from
				// local RF: callsign data naming this gateway and the reflector. The source stays the sender,
				// so the radio shows who sent it.
				lsf.setEncryptionType(M17_ENCRYPTION_TYPE_NONE);
				lsf.setEncryptionSubType(M17_ENCRYPTION_SUB_TYPE_CALLSIGNS);

				unsigned char meta[M17_META_LENGTH_BYTES];
				::memset(meta, 0x00U, M17_META_LENGTH_BYTES);
				CM17Utils::encodeCallsign(linkCallsign(), meta + 0U);
				CM17Utils::encodeCallsign(m_reflector, meta + 6U);
				lsf.setMeta(meta);

				// The LSF has its own CRC, which MMDVMHost checks, the packet's CRC covers only the payload
				lsf.getNetwork(packet + 4U);
				CM17Utils::addCRC16(packet + 4U, M17_LSF_LENGTH_BYTES - M17_CRC_LENGTH_BYTES);

				localNetwork->writePacket(packet, packetLength);
				hangTimer.start();
			}
		}

		if (echoPacketTimer.isRunning() && echoPacketTimer.hasExpired()) {
			localNetwork->writePacket(echoPacket, echoPacketLength);
			echoPacketTimer.stop();
		}

		if (voice != nullptr) {
			if (triggerVoice) {
				uint16_t fn = (buffer[34U] << 8) + (buffer[35U] << 0);
				if ((fn & 0x8000U) == 0x8000U) {
					voice->start();
					triggerVoice = false;
				}
			}

			ret = voice->read(buffer);
			if (ret)
				localNetwork->write(buffer);
		}

		if (remoteSocket != nullptr) {
			sockaddr_storage addr;
			unsigned int addrLen;
			int res = remoteSocket->read(buffer, 99U, addr, addrLen);
			if (res > 0) {
				std::string reply = processCommand(std::string((char*)buffer, res), "");
				if (!reply.empty())
					remoteSocket->write((const unsigned char*)reply.c_str(), (unsigned int)reply.length(), addr, addrLen);
			}
		}

		std::string command;
		while (nextCommand(command)) {
			std::string reply = processCommand(command, " over MQTT");
			if (!reply.empty() && m_mqtt != nullptr)
				m_mqtt->publish("response", reply);
		}

		unsigned int ms = stopWatch.elapsed();
		stopWatch.start();

		if (voice != nullptr)
			voice->clock(ms);

		if (m_writer != nullptr)
			m_writer->clock(ms);

		reflectors.clock(ms);

		localNetwork->clock(ms);

		m_network->clock(ms);

		echo.clock(ms);

		hangTimer.clock(ms);
		echoPacketTimer.clock(ms);
		clockProbe(ms);
		if (hangTimer.isRunning() && hangTimer.hasExpired()) {
			if (revert && !startupReflector.empty() && m_reflector != startupReflector) {
				if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING)
					m_network->unlink();

				// The startup reflector may have left the hosts files since
				// startup (a reload): then unlink rather than follow a null.
				CM17Reflector* refl = reflectors.find(startupReflector);
				if (refl != nullptr) {
					LogMessage("Relinked from %s to %s due to inactivity", m_reflector.c_str(), startupReflector.c_str());

					m_reflector = startupReflector;
					m_addr      = refl->m_addr;
					m_addrLen   = refl->m_addrLen;
					m_module    = startupReflector.at(M17_CALLSIGN_LENGTH - 1U);

					m_status = m_oldStatus = M17_STATUS::LINKING;
					m_network->link(m_reflector, m_addr, m_addrLen, m_module);
					writeJSONLink("linking", "timer");

					if (voice != nullptr) {
						voice->linkedTo(startupReflector);
						voice->start();
					}

					hangTimer.start();
				} else {
					LogWarning("Unable to relink to %s, it is no longer in the hosts files", startupReflector.c_str());

					if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING) {
						m_status = m_oldStatus = M17_STATUS::UNLINKING;
						writeJSONLink("unlinked", "timer");
					}

					if (voice != nullptr) {
						voice->unlinked();
						voice->start();
					}

					m_reflector.clear();

					hangTimer.stop();
				}
			} else if (revert && startupReflector.empty() && (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING)) {
				LogMessage("Unlinking from %s due to inactivity", m_reflector.c_str());

				m_status = m_oldStatus = M17_STATUS::UNLINKING;
				m_network->unlink();
				writeJSONLink("unlinked", "timer");

				if (voice != nullptr) {
					voice->unlinked();
					voice->start();
				}

				m_reflector.clear();

				hangTimer.stop();
			}
		}

		if (ms < 5U)
			CThread::sleep(5U);
	}

	delete voice;

	localNetwork->close();
	delete localNetwork;

	delete[] echoPacket;

	if (remoteSocket != nullptr) {
		remoteSocket->close();
		delete remoteSocket;
	}

	if (m_status == M17_STATUS::LINKED || m_status == M17_STATUS::LINKING)
		m_network->unlink();
	m_network->close();
	delete m_network;

	writeJSONLink("unlinked", "shutdown");
	writeJSONStatus("M17Gateway is stopping");

	if (m_mqtt != nullptr) {
		// Give the MQTT thread time to deliver the last messages, the link message is retained
		CThread::sleep(500U);
		m_mqtt->close();
		delete m_mqtt;
		m_mqtt = nullptr;
	}

	m_gateway = nullptr;

	if (m_gps != nullptr) {
		m_writer->close();
		delete m_writer;
		delete m_gps;
	}

	return 0;
}

void CM17Gateway::createGPS()
{
	if (!m_conf.getAPRSEnabled())
		return;

	std::string callsign  = m_conf.getCallsign();
	std::string rptSuffix = m_conf.getSuffix();
	std::string address   = m_conf.getAPRSAddress();
	unsigned int port     = m_conf.getAPRSPort();
	std::string suffix    = m_conf.getAPRSSuffix();
	bool debug            = m_conf.getDebug();

	m_writer = new CAPRSWriter(callsign, rptSuffix, address, port, debug);

	unsigned int txFrequency = m_conf.getTxFrequency();
	unsigned int rxFrequency = m_conf.getRxFrequency();
	std::string desc         = m_conf.getAPRSDescription();
	std::string symbol  	 = m_conf.getAPRSSymbol();

	m_writer->setInfo(txFrequency, rxFrequency, desc, symbol);

	// bool enabled = m_conf.getGPSDEnabled();
	// if (enabled) {
	//        std::string address = m_conf.getGPSDAddress();
	//        std::string port    = m_conf.getGPSDPort();
	//
	//        m_writer->setGPSDLocation(address, port);
	// } else {
	        float latitude  = m_conf.getLatitude();
                float longitude = m_conf.getLongitude();
                int height      = m_conf.getHeight();

                m_writer->setStaticLocation(latitude, longitude, height);
	// }

	bool ret = m_writer->open();
	if (!ret) {
		delete m_writer;
		m_writer = nullptr;
		return;
	}

	m_gps = new CGPSHandler(callsign, rptSuffix, m_writer);
}

void CM17Gateway::writeJSONStatus(const std::string& message)
{
	nlohmann::json json;

	json["timestamp"] = CUtils::createTimestamp();
	json["message"]   = message;

	WriteJSON("status", json, false);
}

// As G4KLX's gateway programs' link message, with protocol "m17" and the module in its own field.
// A completed link is "linking" with the reason "established". Retained, so a dashboard that
// starts later still sees the current link.
void CM17Gateway::writeJSONLink(const std::string& action, const std::string& reason)
{
	nlohmann::json json;

	json["timestamp"] = CUtils::createTimestamp();
	json["action"]    = action;

	if (!reason.empty())
		json["reason"] = reason;

	if (action != "unlinked" && !m_reflector.empty()) {
		json["reflector"] = trim(m_reflector.substr(0U, M17_CALLSIGN_LENGTH - 1U));

		char module = m_reflector.at(m_reflector.length() - 1U);
		if (module >= 'A' && module <= 'Z')
			json["module"] = std::string(1U, module);
	}

	json["protocol"] = "m17";

	WriteJSON("link", json, true);
}

// MQTT messages arrive on the MQTT thread, so commands are queued for the main loop
void CM17Gateway::queueCommand(const std::string& command)
{
	std::lock_guard<std::mutex> lock(m_commandMutex);
	m_commands.push_back(command);
}

bool CM17Gateway::nextCommand(std::string& command)
{
	std::lock_guard<std::mutex> lock(m_commandMutex);
	if (m_commands.empty())
		return false;

	command = m_commands.front();
	m_commands.pop_front();
	return true;
}

void CM17Gateway::onCommand(const unsigned char* command, unsigned int length)
{
	assert(command != nullptr);

	if (m_gateway != nullptr)
		m_gateway->queueCommand(std::string((const char*)command, length));
}
