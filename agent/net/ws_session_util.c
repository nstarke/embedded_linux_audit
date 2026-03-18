// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ws_session_util.h"

#include "ws_client.h"
#include "ws_frame_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool ela_ws_response_headers_complete(const char *response, size_t response_len)
{
	if (!response || response_len < 4)
		return false;

	return response[response_len - 4] == '\r' &&
	       response[response_len - 3] == '\n' &&
	       response[response_len - 2] == '\r' &&
	       response[response_len - 1] == '\n';
}

bool ela_ws_handshake_response_is_unauthorized(const char *response)
{
	return response && strstr(response, " 401 ") != NULL;
}

int ela_ws_validate_handshake_response(const char *response,
				       char *errbuf,
				       size_t errbuf_len)
{
	long code = 0;
	const char *sp;

	if (!response || strncmp(response, "HTTP/1.1 ", 9) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "malformed response");
		return -1;
	}

	if (!strncmp(response, "HTTP/1.1 101", 12))
		return 0;

	sp = strchr(response, ' ');
	if (sp)
		code = strtol(sp + 1, NULL, 10);

	if (errbuf && errbuf_len) {
		if (code == 401) {
			snprintf(errbuf, errbuf_len,
				 "server returned 401 Unauthorized");
		} else {
			snprintf(errbuf, errbuf_len,
				 "server returned unexpected response: %.40s",
				 response);
		}
	}
	return -1;
}

int ela_ws_build_heartbeat_ack(const char *date_str, char *out, size_t out_sz)
{
	if (!date_str || !*date_str || !out || out_sz == 0)
		return -1;

	return snprintf(out, out_sz,
			"{\"_type\":\"heartbeat_ack\",\"date\":\"%s\"}",
			date_str) >= (int)out_sz ? -1 : 0;
}

void ela_ws_classify_incoming_frame(uint8_t opcode,
				    const char *payload,
				    size_t payload_len,
				    struct ela_ws_frame_action *out)
{
	if (!out)
		return;

	memset(out, 0, sizeof(*out));
	if (opcode == ELA_WS_OPCODE_CLOSE) {
		out->terminate_session = 1;
		return;
	}
	if (opcode == ELA_WS_OPCODE_PING) {
		out->send_pong = 1;
		return;
	}
	if (opcode == ELA_WS_OPCODE_TEXT && payload && payload_len > 0) {
		if (strstr(payload, "\"_type\":\"heartbeat\""))
			out->send_heartbeat_ack = 1;
		else
			out->forward_to_repl = 1;
	}
}

int ela_ws_build_zero_mask_control_frame(uint8_t opcode,
					 uint8_t frame[6],
					 size_t *frame_len_out)
{
	if (!frame || !frame_len_out)
		return -1;

	frame[0] = 0x80 | opcode;
	frame[1] = 0x80;
	frame[2] = 0;
	frame[3] = 0;
	frame[4] = 0;
	frame[5] = 0;
	*frame_len_out = 6;
	return 0;
}

int ela_ws_build_ping_frame(uint8_t frame[6], size_t *frame_len_out)
{
	return ela_ws_build_zero_mask_control_frame(ELA_WS_OPCODE_PING, frame, frame_len_out);
}

bool ela_ws_child_wait_exited(int waitpid_result)
{
	return waitpid_result > 0;
}

bool ela_ws_child_output_should_break(ssize_t read_len)
{
	return read_len <= 0;
}

int ela_ws_interactive_exit_code(int child_exited)
{
	return child_exited ? ELA_WS_EXIT_CLEAN : 0;
}
