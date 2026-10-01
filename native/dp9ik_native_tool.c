#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drawterm/drawterm_wrapper.h"

static int
decode_hex(const char *hex, unsigned char *buffer, size_t size)
{
	size_t i;

	if(strlen(hex) != size * 2)
		return 0;

	for(i = 0; i < size; i++){
		char hi = hex[i * 2];
		char lo = hex[i * 2 + 1];
		int hi_val;
		int lo_val;

		if(!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo))
			return 0;

		hi_val = hi <= '9' ? hi - '0' : tolower((unsigned char)hi) - 'a' + 10;
		lo_val = lo <= '9' ? lo - '0' : tolower((unsigned char)lo) - 'a' + 10;
		buffer[i] = (unsigned char)((hi_val << 4) | lo_val);
	}

	return 1;
}

static void
print_hex(const unsigned char *buffer, size_t size)
{
	size_t i;

	for(i = 0; i < size; i++)
		printf("%02x", buffer[i]);
	printf("\n");
}

static int
handle_sizes(void)
{
	printf("ticketreq=%zu\n", sizeof(Ticketreq));
	printf("ticket=%zu\n", sizeof(Ticket));
	printf("authenticator=%zu\n", sizeof(Authenticator));
	printf("authkey=%zu\n", sizeof(Authkey));
	printf("pakstate=%zu\n", sizeof(PAKpriv));
	return 0;
}

static int
handle_passtokey(const char *password)
{
	Authkey key;

	memset(&key, 0, sizeof(key));
	passtokey(&key, (char*)password);
	print_hex((unsigned char*)&key, sizeof(key));
	return 0;
}

static int
handle_authpak_hash(const char *authkey_hex, const char *user)
{
	Authkey key;

	if(!decode_hex(authkey_hex, (unsigned char*)&key, sizeof(key)))
		return 2;

	authpak_hash(&key, (char*)user);
	print_hex((unsigned char*)&key, sizeof(key));
	return 0;
}

static int
handle_authpak_new(const char *authkey_hex, const char *is_client_text)
{
	Authkey key;
	PAKpriv state;
	uchar y[PAKYLEN];
	int is_client;

	if(!decode_hex(authkey_hex, (unsigned char*)&key, sizeof(key)))
		return 2;

	is_client = strcmp(is_client_text, "1") == 0;
	authpak_new(&state, &key, y, is_client);
	print_hex((unsigned char*)&state, sizeof(state));
	print_hex(y, sizeof(y));
	return 0;
}

static int
handle_authpak_finish(const char *state_hex, const char *authkey_hex, const char *peer_hex)
{
	Authkey key;
	PAKpriv state;
	uchar y[PAKYLEN];

	if(!decode_hex(state_hex, (unsigned char*)&state, sizeof(state)))
		return 2;
	if(!decode_hex(authkey_hex, (unsigned char*)&key, sizeof(key)))
		return 2;
	if(!decode_hex(peer_hex, y, sizeof(y)))
		return 2;
	if(authpak_finish(&state, &key, y) != 0)
		return 3;

	print_hex((unsigned char*)&key, sizeof(key));
	return 0;
}

static int
handle_ticket_marshal(const char *authkey_hex, const char *ticket_hex)
{
	Authkey key;
	Ticket ticket;
	uchar buffer[MAXTICKETLEN];
	int size;

	if(!decode_hex(authkey_hex, (unsigned char*)&key, sizeof(key)))
		return 2;
	if(!decode_hex(ticket_hex, (unsigned char*)&ticket, sizeof(ticket)))
		return 2;

	size = convT2M(&ticket, (char*)buffer, sizeof(buffer), &key);
	if(size <= 0)
		return 3;

	print_hex(buffer, (size_t)size);
	return 0;
}

static int
handle_ticket_unmarshal(const char *authkey_hex, const char *wire_hex)
{
	Authkey key;
	Ticket ticket;
	size_t wire_size;
	uchar *wire;
	int size;

	wire_size = strlen(wire_hex) / 2;
	wire = malloc(wire_size);
	if(wire == NULL)
		return 4;
	if(!decode_hex(authkey_hex, (unsigned char*)&key, sizeof(key))
	|| !decode_hex(wire_hex, wire, wire_size)){
		free(wire);
		return 2;
	}

	memset(&ticket, 0, sizeof(ticket));
	size = convM2T((char*)wire, (int)wire_size, &ticket, &key);
	free(wire);

	if(size <= 0){
		printf("0\n");
		return 0;
	}

	printf("%d\n", size);
	print_hex((unsigned char*)&ticket, sizeof(ticket));
	return 0;
}

static int
handle_authenticator_marshal(const char *ticket_hex, const char *authenticator_hex)
{
	Ticket ticket;
	Authenticator authenticator;
	uchar buffer[MAXAUTHENTLEN];
	int size;

	if(!decode_hex(ticket_hex, (unsigned char*)&ticket, sizeof(ticket)))
		return 2;
	if(!decode_hex(authenticator_hex, (unsigned char*)&authenticator, sizeof(authenticator)))
		return 2;

	size = convA2M(&authenticator, (char*)buffer, sizeof(buffer), &ticket);
	if(size <= 0)
		return 3;

	print_hex(buffer, (size_t)size);
	return 0;
}

static int
handle_authenticator_unmarshal(const char *ticket_hex, const char *wire_hex)
{
	Ticket ticket;
	Authenticator authenticator;
	size_t wire_size;
	uchar *wire;
	int size;

	wire_size = strlen(wire_hex) / 2;
	wire = malloc(wire_size);
	if(wire == NULL)
		return 4;
	if(!decode_hex(ticket_hex, (unsigned char*)&ticket, sizeof(ticket))
	|| !decode_hex(wire_hex, wire, wire_size)){
		free(wire);
		return 2;
	}

	memset(&authenticator, 0, sizeof(authenticator));
	size = convM2A((char*)wire, (int)wire_size, &authenticator, &ticket);
	free(wire);

	if(size <= 0){
		printf("0\n");
		return 0;
	}

	printf("%d\n", size);
	print_hex((unsigned char*)&authenticator, sizeof(authenticator));
	return 0;
}

#ifndef DP9IK_NATIVE_TOOL_NO_MAIN
int
main(int argc, char **argv)
{
	if(argc < 2)
		return 1;
	if(strcmp(argv[1], "sizes") == 0)
		return handle_sizes();
	if(strcmp(argv[1], "passtokey") == 0 && argc == 3)
		return handle_passtokey(argv[2]);
	if(strcmp(argv[1], "authpak_hash") == 0 && argc == 4)
		return handle_authpak_hash(argv[2], argv[3]);
	if(strcmp(argv[1], "authpak_new") == 0 && argc == 4)
		return handle_authpak_new(argv[2], argv[3]);
	if(strcmp(argv[1], "authpak_finish") == 0 && argc == 5)
		return handle_authpak_finish(argv[2], argv[3], argv[4]);
	if(strcmp(argv[1], "ticket_marshal") == 0 && argc == 4)
		return handle_ticket_marshal(argv[2], argv[3]);
	if(strcmp(argv[1], "ticket_unmarshal") == 0 && argc == 4)
		return handle_ticket_unmarshal(argv[2], argv[3]);
	if(strcmp(argv[1], "authenticator_marshal") == 0 && argc == 4)
		return handle_authenticator_marshal(argv[2], argv[3]);
	if(strcmp(argv[1], "authenticator_unmarshal") == 0 && argc == 4)
		return handle_authenticator_unmarshal(argv[2], argv[3]);
	return 1;
}
#endif
