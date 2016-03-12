#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
//minimum arguments required for running server
#define MIN_ARGS 2
//Buffer size for reading client requests
#define READ_BUFFER_SIZE 400
//buffer size for reading from files and writing to socket
#define CHUNKED_READ_WRITE_BUFFER_SIZE 1000
#define TRUE 1
#define FALSE 0
//response header size
#define RESPONSE_HEADER_SIZE 256

void signal_error(char *err_msg);
char *getRequestedResource(char *request);
void getErrorHeader(int error_code, char* header);
int isValidRequest(char *request);
char *generateFileFoundHeader(unsigned long size, int is_html, int *header_size);
void writeFileToSocket(int socket_fd, int file_fd, struct sockaddr_in *client,
		socklen_t *client_addr_size);
void generateFileFoundHeaderAndWriteToSocket(int file_size, char* resource_name,
		int socket_fd, struct sockaddr_in *client, socklen_t *client_addr_size);
void generateAndWriteErrorHeader(int socket_fd, int errno,
		struct sockaddr_in *client, socklen_t *client_addr_size);
void getHTTPRequest(int socket_fd, int *valid, char **resource, char *request,
		int *readc, struct sockaddr_in *client, socklen_t *client_addr_size);
void processRequest(int socket_fd);
/*
 * Prints the error to the standard error stream and exits the program
 */
void signal_error(char *err_msg) {
	fprintf(stderr, err_msg);
	fprintf(stderr, "shutting down");
	exit(1);
}
int main(int argc, char *argv[]) {
	if (!argc < MIN_ARGS) {
		int bind_status, socket_file_descr, port;
		struct sockaddr_in server;

		port = atoi(argv[1]);
		socket_file_descr = socket(AF_INET, SOCK_DGRAM, 0);
		if (socket_file_descr == -1) {
			signal_error("Failed creating a socket for the server");
		}
		memset(&server, 0, sizeof(server));
		//populate the server address details
		server.sin_family = AF_INET;
		//assigning the network byte order equivalent of port no
		server.sin_port = htons(port);
		server.sin_addr.s_addr = INADDR_ANY;
		//bind socket
		bind_status = bind(socket_file_descr, (struct sockaddr *) &server,
				sizeof(server));
		if (bind_status == -1) {
			signal_error("Socket binding failed");
		}
		while (1) {
			processRequest(socket_file_descr);
		}
	} else {
		signal_error(
				"insufficient arguments. Port # is required for server boot up.");
	}
}

/**
 * Check if the http request is valid.
 */
int isValidRequest(char *request) {
	int i;
	int valid = 1;
	if (strlen(request) < 12) {
		valid = 0;
		return valid;

	}
	//checking if the first three char are GET
	if (!(request[0] == 'G' && request[1] == 'E' && request[2] == 'T'
			&& request[3] == ' ')) {
		valid = 0;
		return valid;
	}
	for (i = 4;
			!(request[i] == '\r' || request[i] == '\n' || request[i] == ' ');
			i++)
		;
	if (request[i] == '\r' || request[i] == '\n') {
		valid = 0;
		return valid;
	}
	//checking if the request header's first line has the HTTP protocol mentioned
	if (!(request[i + 1] == 'H' && request[i + 2] == 'T'
			&& request[i + 3] == 'T' && request[i + 4] == 'P')) {
		valid = 0;
		return valid;
	}
	return valid;
}
/**
 * Parses the resource/file name requested in the HTTP request header
 */
char* getRequestedResource(char *request) {
	char *start = strchr(request, ' ');
	start += 1;
	char *end = strchr(start, ' ');
	end -= 1;
	char *resource = (char *) calloc(1, end - start + 1);
	memcpy(resource, start, end - start + 1);
	resource[end - start + 1] = '\0';
	return resource;
}
/**
 * get HTTP request from the socket and evaluate/parse
 */
void getHTTPRequest(int socket_fd, int *valid, char **resource, char *request,
		int *readc, struct sockaddr_in *client, socklen_t *client_addr_size) {
	*client_addr_size = sizeof client;
	*readc = recvfrom(socket_fd, request, 400, 0, (struct sockaddr *) client,
			client_addr_size);
	if (readc < 0) {
		signal_error("Error in reading client request");
	}
	//checking if request is valid
	*valid = isValidRequest(request);
	//parsing the request for requested resource from http request header
	*resource = getRequestedResource(request);
}
/**
 * Processes Requests.
 * Reads the request from the socket. Checks if the request is a valid request.
 * In case of invalid request, returns a response with bad request error code 500.
 * In case it is a valid request, checks for the resource in file system.
 * If the resource is found, then it sends the appropriate headers and the requested resource.
 * If the resource is not found, then sends the Resource Not Found, 404 Error header
 */
void processRequest(int socket_fd) {
	struct sockaddr_in client;
	socklen_t client_addr_size;
	int validRequest;
	char *resource;
	char request[READ_BUFFER_SIZE] = "";
	int readc;
	getHTTPRequest(socket_fd, &validRequest, &resource, request, &readc,
			&client, &client_addr_size);
	if (!validRequest) {
		//handle invalid request
		//if(readc==0), client has shutdown
		if (!readc == 0) {
			generateAndWriteErrorHeader(socket_fd, 500, &client,
					&client_addr_size);
		}
		memset(request, 0, READ_BUFFER_SIZE);
	}
	//Get the file descriptor of the requested resource
	int req_file_fd = open(resource + 1, O_RDONLY);
	free(resource);
	if (req_file_fd == -1) {
		//case:file not found
		//Generate and write 404 error in response
		generateAndWriteErrorHeader(socket_fd, 404, &client, &client_addr_size);
	} else {
		//case:file found
		//getting the file size
		struct stat file_stat;
		fstat(req_file_fd, &file_stat);
		unsigned long size = (unsigned long) file_stat.st_size;
		//Generate file found header and write it in response.
		generateFileFoundHeaderAndWriteToSocket(size, resource + 1, socket_fd,
				&client, &client_addr_size);
		//Write file to response
		writeFileToSocket(socket_fd, req_file_fd, &client, &client_addr_size);
		//free(resource);
	}
}

void generateFileFoundHeaderAndWriteToSocket(int file_size, char* resource_name,
		int socket_fd, struct sockaddr_in *client, socklen_t *client_addr_size) {
	int header_size = 0;
	char *header = generateFileFoundHeader(file_size,
			(strstr(resource_name, ".html") != NULL) ? TRUE : FALSE,
			&header_size);
	sendto(socket_fd, header, header_size, 0, (struct sockaddr *) client,
			*client_addr_size);
}

void writeFileToSocket(int socket_fd, int file_fd, struct sockaddr_in *client,
		socklen_t *client_addr_size) {
	unsigned char file_buffer[CHUNKED_READ_WRITE_BUFFER_SIZE];
	//bytes read from file into buffer
	int readc;
	//bytes written to socket
	int writec;
	//Read, write in chunks
	for (readc = read(file_fd, file_buffer, (sizeof file_buffer) - 1);
			readc > 0;
			readc = read(file_fd, file_buffer, (sizeof file_buffer) - 1)) {
		unsigned char *temp = file_buffer;
		for (writec = sendto(socket_fd,
				temp,
				CHUNKED_READ_WRITE_BUFFER_SIZE, 0,
				(struct sockaddr *) client, *client_addr_size); readc > 0 && writec > 0;
				readc -= writec, temp += writec, writec = sendto(socket_fd,
						temp,
						file_buffer + CHUNKED_READ_WRITE_BUFFER_SIZE - temp, 0,
						(struct sockaddr *) client, *client_addr_size))
			;
	}
	time_t current_time = time(NULL);
	printf("\n last byte of response written at:%s", ctime(&current_time));
	if (readc < 0 || writec < 0) {
		signal_error(
				"Error occured during copying file from file sytem to socket");
	}
	close(file_fd);
}

void generateAndWriteErrorHeader(int socket_fd, int errno,
		struct sockaddr_in *client, socklen_t *client_addr_size) {
	char output[RESPONSE_HEADER_SIZE];
	getErrorHeader(errno, output);
	sendto(socket_fd, output, sizeof(output), 0, (struct sockaddr *) client,
			*client_addr_size);
}

/**
 *Generates the error header for the given error code
 **/
void getErrorHeader(int error, char *header) {
	//getting the current time
	time_t current_time = time(NULL);
	//ctime has a /n appended to the returned string, hence only a single n at the end of header
	snprintf(header, RESPONSE_HEADER_SIZE,
			"HTTP/1.1 %d %s\r\n Server: X\r\nContent-Length: 0\r\nDate: %s\n",
			error, (error == 404 ? "Not Found" : "Bad Request"),
			ctime(&current_time));
}

/* Generates the header for a file being sent as a reponse.
 **/
char *generateFileFoundHeader(unsigned long size, int is_html, int *header_size) {
	char header[RESPONSE_HEADER_SIZE] = "";
	//getting current time
	time_t current_time = time(NULL);
	//ctime has a /n appended to the returned string, hence only a single n at the end of header
	//generating header
	snprintf(header, sizeof header,
			"HTTP/1.1 %d %s\r\nServer:X\r\nContent-Length:%lu\r\nContent-Type:%s\r\nDate:%s\n",
			200,

			"OK", size, (is_html) ? "text/html" : "application",
			ctime(&current_time));
	//trimming the header
	char *header_trimmed = (char *) calloc(1, strlen(header) + 1);
	{
		int i = 0;
		for (; i < strlen(header) + 1; i++) {
			header_trimmed[i] = header[i];
		}
	}
	*header_size = strlen(header) + 1;
	return header_trimmed;
}
