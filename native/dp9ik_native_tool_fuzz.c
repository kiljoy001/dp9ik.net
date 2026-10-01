#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DP9IK_NATIVE_TOOL_NO_MAIN
#include "dp9ik_native_tool.c"

#define MAX_FUZZ_TEXT 256
#define MAX_FUZZ_WIRE 256

static void
silence_stdout(void)
{
	int devnull;

	devnull = open("/dev/null", O_WRONLY);
	if(devnull < 0)
		return;
	dup2(devnull, STDOUT_FILENO);
	close(devnull);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	silence_stdout();
	(void)handle_sizes();
	return 0;
}

static void
hex_encode(const unsigned char *src, size_t len, char *dest)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for(i = 0; i < len; i++){
		dest[i * 2] = digits[src[i] >> 4];
		dest[i * 2 + 1] = digits[src[i] & 0x0f];
	}
	dest[len * 2] = '\0';
}

static size_t
copy_padded(unsigned char *dest, size_t dest_len, const uint8_t **cursor, size_t *remaining)
{
	size_t take;

	memset(dest, 0, dest_len);
	take = *remaining < dest_len ? *remaining : dest_len;
	if(take > 0){
		memcpy(dest, *cursor, take);
		*cursor += take;
		*remaining -= take;
	}
	return take;
}

static size_t
copy_bounded(unsigned char *dest, size_t dest_len, const uint8_t **cursor, size_t *remaining)
{
	size_t take;

	memset(dest, 0, dest_len);
	if(*remaining == 0)
		return 0;

	take = **cursor % (dest_len + 1);
	(*cursor)++;
	(*remaining)--;
	if(take > *remaining)
		take = *remaining;
	if(take > 0){
		memcpy(dest, *cursor, take);
		*cursor += take;
		*remaining -= take;
	}
	return take;
}

static void
copy_text(char *dest, size_t dest_len, const uint8_t *data, size_t size)
{
	size_t take;

	if(dest_len == 0)
		return;

	take = size < dest_len - 1 ? size : dest_len - 1;
	memcpy(dest, data, take);
	dest[take] = '\0';
}

static void
fuzz_decode_hex_path(const uint8_t *data, size_t size)
{
	char text[MAX_FUZZ_TEXT + 1];
	unsigned char buffer[MAX_FUZZ_TEXT / 2];
	size_t text_len;
	size_t target_len;

	text_len = size < MAX_FUZZ_TEXT ? size : MAX_FUZZ_TEXT;
	copy_text(text, sizeof(text), data, text_len);
	target_len = text_len / 2;
	if(target_len > sizeof(buffer))
		target_len = sizeof(buffer);
	(void)decode_hex(text, buffer, target_len);
}

static void
fuzz_passtokey_path(const uint8_t *data, size_t size)
{
	char password[MAX_FUZZ_TEXT + 1];

	copy_text(password, sizeof(password), data, size < MAX_FUZZ_TEXT ? size : MAX_FUZZ_TEXT);
	(void)handle_passtokey(password);
}

static void
fuzz_authpak_hash_path(const uint8_t *data, size_t size)
{
	const uint8_t *cursor;
	size_t remaining;
	unsigned char key[sizeof(Authkey)];
	char key_hex[sizeof(Authkey) * 2 + 1];
	char user[MAX_FUZZ_TEXT + 1];

	cursor = data;
	remaining = size;
	copy_padded(key, sizeof(key), &cursor, &remaining);
	hex_encode(key, sizeof(key), key_hex);
	copy_text(user, sizeof(user), cursor, remaining < MAX_FUZZ_TEXT ? remaining : MAX_FUZZ_TEXT);
	(void)handle_authpak_hash(key_hex, user);
}

static void
fuzz_authpak_new_path(const uint8_t *data, size_t size)
{
	const uint8_t *cursor;
	size_t remaining;
	unsigned char key[sizeof(Authkey)];
	char key_hex[sizeof(Authkey) * 2 + 1];

	cursor = data;
	remaining = size;
	copy_padded(key, sizeof(key), &cursor, &remaining);
	hex_encode(key, sizeof(key), key_hex);
	(void)handle_authpak_new(key_hex, remaining > 0 && (*cursor & 1) != 0 ? "1" : "0");
}

static void
fuzz_authpak_finish_path(const uint8_t *data, size_t size)
{
	const uint8_t *cursor;
	size_t remaining;
	unsigned char state[sizeof(PAKpriv)];
	unsigned char key[sizeof(Authkey)];
	unsigned char peer[PAKYLEN];
	char state_hex[sizeof(PAKpriv) * 2 + 1];
	char key_hex[sizeof(Authkey) * 2 + 1];
	char peer_hex[PAKYLEN * 2 + 1];

	cursor = data;
	remaining = size;
	copy_padded(state, sizeof(state), &cursor, &remaining);
	copy_padded(key, sizeof(key), &cursor, &remaining);
	copy_padded(peer, sizeof(peer), &cursor, &remaining);
	hex_encode(state, sizeof(state), state_hex);
	hex_encode(key, sizeof(key), key_hex);
	hex_encode(peer, sizeof(peer), peer_hex);
	(void)handle_authpak_finish(state_hex, key_hex, peer_hex);
}

static void
fuzz_ticket_marshal_path(const uint8_t *data, size_t size)
{
	const uint8_t *cursor;
	size_t remaining;
	unsigned char key[sizeof(Authkey)];
	unsigned char ticket[sizeof(Ticket)];
	char key_hex[sizeof(Authkey) * 2 + 1];
	char ticket_hex[sizeof(Ticket) * 2 + 1];

	cursor = data;
	remaining = size;
	copy_padded(key, sizeof(key), &cursor, &remaining);
	copy_padded(ticket, sizeof(ticket), &cursor, &remaining);
	hex_encode(key, sizeof(key), key_hex);
	hex_encode(ticket, sizeof(ticket), ticket_hex);
	(void)handle_ticket_marshal(key_hex, ticket_hex);
}

static void
fuzz_ticket_unmarshal_path(const uint8_t *data, size_t size)
{
	const uint8_t *cursor;
	size_t remaining;
	unsigned char key[sizeof(Authkey)];
	unsigned char wire[MAX_FUZZ_WIRE];
	size_t wire_len;
	char key_hex[sizeof(Authkey) * 2 + 1];
	char wire_hex[MAX_FUZZ_WIRE * 2 + 1];

	cursor = data;
	remaining = size;
	copy_padded(key, sizeof(key), &cursor, &remaining);
	wire_len = copy_bounded(wire, sizeof(wire), &cursor, &remaining);
	hex_encode(key, sizeof(key), key_hex);
	hex_encode(wire, wire_len, wire_hex);
	(void)handle_ticket_unmarshal(key_hex, wire_hex);
}

static void
fuzz_authenticator_marshal_path(const uint8_t *data, size_t size)
{
	const uint8_t *cursor;
	size_t remaining;
	unsigned char ticket[sizeof(Ticket)];
	unsigned char authenticator[sizeof(Authenticator)];
	char ticket_hex[sizeof(Ticket) * 2 + 1];
	char authenticator_hex[sizeof(Authenticator) * 2 + 1];

	cursor = data;
	remaining = size;
	copy_padded(ticket, sizeof(ticket), &cursor, &remaining);
	copy_padded(authenticator, sizeof(authenticator), &cursor, &remaining);
	hex_encode(ticket, sizeof(ticket), ticket_hex);
	hex_encode(authenticator, sizeof(authenticator), authenticator_hex);
	(void)handle_authenticator_marshal(ticket_hex, authenticator_hex);
}

static void
fuzz_authenticator_unmarshal_path(const uint8_t *data, size_t size)
{
	const uint8_t *cursor;
	size_t remaining;
	unsigned char ticket[sizeof(Ticket)];
	unsigned char wire[MAX_FUZZ_WIRE];
	size_t wire_len;
	char ticket_hex[sizeof(Ticket) * 2 + 1];
	char wire_hex[MAX_FUZZ_WIRE * 2 + 1];

	cursor = data;
	remaining = size;
	copy_padded(ticket, sizeof(ticket), &cursor, &remaining);
	wire_len = copy_bounded(wire, sizeof(wire), &cursor, &remaining);
	hex_encode(ticket, sizeof(ticket), ticket_hex);
	hex_encode(wire, wire_len, wire_hex);
	(void)handle_authenticator_unmarshal(ticket_hex, wire_hex);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_decode_hex_path(data, size);
	fuzz_passtokey_path(data, size);
	fuzz_authpak_hash_path(data, size);
	fuzz_authpak_new_path(data, size);
	fuzz_authpak_finish_path(data, size);
	fuzz_ticket_marshal_path(data, size);
	fuzz_ticket_unmarshal_path(data, size);
	fuzz_authenticator_marshal_path(data, size);
	fuzz_authenticator_unmarshal_path(data, size);
	return 0;
}
