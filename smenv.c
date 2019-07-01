#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <curl/curl.h>

#include "sha.h"
#include "hmac.h"
#include "jsmn.h"

char* method = "POST";
char* service = "secretsmanager";
char* host = "secretsmanager.us-east-1.amazonaws.com";
char* region = "us-east-1";
char* endpoint = "https://secretsmanager.us-east-1.amazonaws.com/";
char* content_type = "application/x-amz-json-1.1";
char* amz_target = "secretsmanager.GetSecretValue";

char* canonical_uri = "/";
char* canonical_querystring = "";
char* signed_headers = "content-type;host;x-amz-date;x-amz-target";
int debug = 0;

struct MemoryStruct {
  char *memory;
  size_t size;
};

unsigned char* sign(const unsigned char* akey, const unsigned char* msg) {
	unsigned char* mac = (unsigned char*) malloc(SHA256_DIGEST_SIZE+1 * sizeof(unsigned char));
  mac[SHA256_DIGEST_SIZE] = 0;
  int len = strlen((char *) akey);
  if (len < 32) {
    len = 32; // Bug -- if aKey has a zero as an element, it is interpreted as the end of list
  }
	hmac_sha256(akey, len, msg, strlen((char *)msg), mac, SHA256_DIGEST_SIZE);
	return mac;
}

char* hex_dump(unsigned char* in) {
  int len = strlen((char *) in);
	char* ret = (char*) calloc((len+1) * 2, sizeof(char));
	for (int i = 0; i < len; i++) {
		sprintf(ret+i+i, "%02x", in[i]);
	}
	return ret;
}

unsigned char* getSignatureKey(const unsigned char* key, const unsigned char* date_stamp,
	const unsigned char* region_name, const unsigned char* service_name) {
		unsigned char* intermediate = (unsigned char*) calloc(45, sizeof(unsigned char));
		strcpy( (char*) intermediate, "AWS4" );
		strcpy( (char*) intermediate+4, (char*) key);

		unsigned char* kDate = sign((unsigned char*)intermediate, date_stamp);
    free(intermediate);
		unsigned char* kRegion = sign(kDate, region_name);
    free(kDate);
		unsigned char* kService = sign(kRegion, service_name);
    free(kRegion);
		unsigned char* kSigning = sign(kService, (unsigned char *) "aws4_request");
		return kSigning;
}

char* hex_sha(const char* input) {
	unsigned char *sha = calloc(300, sizeof(unsigned char));
	sha256((const unsigned char*)input, strlen(input), (unsigned char *) sha);
	char* hexa_dump = (char*) calloc(64, sizeof(char));
	for (int i = 0; i < 32; i++) {
		sprintf(hexa_dump+i+i, "%02x", sha[i]);
	}
	return hexa_dump;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

void get_times(char* amz_date, char* date_stamp) {
	time_t t = time(NULL);
	struct tm tm = *gmtime(&t);
	sprintf(amz_date, "%d%02d%02dT%02d%02d%02dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	sprintf(date_stamp, "%02d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday );
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}


int main(int argc, char **argv) {
  int arg_len = 0;
  for (int i = 1; i < argc; i++) {
    arg_len += strlen(argv[i]) + 1;
  }
  char * command = (char *) malloc(arg_len * sizeof(char));
  for (int i = 1; i < argc; i++) {
    strcpy(command + strlen(command), argv[i]);
    strcpy(command + strlen(command), " ");
  }

	char * access_key = getenv("ACCESS_KEY_ID");
	char * secret_key = getenv("SECRET_ACCESS_KEY");
	if (!(secret_key && secret_key))  {
		printf("Keys not set\n");
		return 1;
	}

	char amz_date[18];
	char date_stamp[10];
	get_times(amz_date, date_stamp);

	char canonical_headers[300];
  sprintf(canonical_headers, "content-type:%s\nhost:%s\nx-amz-date:%s\nx-amz-target:%s\n", content_type,  host,  amz_date, amz_target);

	const char* request_parameters = "{\"SecretId\": \"tugboat/test\"}";
	char* payload_hash = hex_sha(request_parameters);
	char canonical_request[600];
	sprintf(canonical_request, "%s\n%s\n%s\n%s\n%s\n%s", method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash);
  char* canonical_request_hash = hex_sha(canonical_request);
	char* algorithm = "AWS4-HMAC-SHA256";
	char credential_scope[300];
	sprintf(credential_scope, "%s/%s/%s/%s", date_stamp, region, service, "aws4_request");
	char string_to_sign[1000];
	sprintf(string_to_sign, "%s\n%s\n%s\n%s", algorithm, amz_date, credential_scope, canonical_request_hash);
  free(canonical_request_hash);

	unsigned char * signing_key = getSignatureKey((unsigned char *)secret_key, (unsigned char *) date_stamp, (unsigned char *) region, (unsigned char *) service);
  unsigned char * signature = sign(signing_key, (unsigned char *) string_to_sign);

	char authorization_header[1000];
	sprintf(authorization_header, "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", algorithm, access_key, credential_scope, signed_headers, hex_dump(signature));
  if (debug) {
    printf("Canonical Request:\n%s\n\n", canonical_request);
    printf("string to sign:\n%s\n\n", string_to_sign);
    printf("request signature:\n%s\n\n", hex_dump(signature));
    printf("auth header:\n%s\n\n", authorization_header);
  }
	// CURL
	CURL *curl;
  CURLcode res;
	struct MemoryStruct chunk;

  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
  chunk.size = 0;    /* no data at this point */

	curl_global_init(CURL_GLOBAL_ALL);

	for (int i = 0; i < 10; i ++) {
		curl = curl_easy_init();
		if(curl) {
			break;
		}
		if (i == 9) {
			printf("Cannot create curl.");
			return 1;
		}
	}

 	// curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_URL, endpoint);
	struct curl_slist *list = NULL;
	list = curl_slist_append(list, "Content-Type: application/x-amz-json-1.1");
	char curl_amz_date[200];
	sprintf(curl_amz_date, "X-Amz-Date: %s", amz_date);
	list = curl_slist_append(list, curl_amz_date);
	list = curl_slist_append(list, "X-Amz-Target: secretsmanager.GetSecretValue");
	char curl_authorization_header[1000];
	sprintf(curl_authorization_header, "Authorization: %s", authorization_header);
	list = curl_slist_append(list, curl_authorization_header);
	// list = curl_slist_append(list, "Transfer-Encoding: chunked");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

  /* Now specify the POST data */
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_parameters);
  res = curl_easy_perform(curl);
  /* Check for errors */
  if(res != CURLE_OK)
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  /* always cleanup */
	printf("%s\n", chunk.memory);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  jsmn_parser p;
  jsmntok_t t[128];
  jsmn_init(&p);
  int r = jsmn_parse(&p, chunk.memory, strlen(chunk.memory), t, 15);

  char * secretString;
  for (int i = 1; i < r; i++) {
    if (jsoneq(chunk.memory, &t[i], "SecretString") == 0) {
      /* We may use strndup() to fetch string value */
      secretString = (char *) malloc((t[i + 1].end - t[i + 1].start) * sizeof(char *));
      sprintf(secretString, "%.*s", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
      break;
    }
  }

  jsmn_init(&p);
  r = jsmn_parse(&p, secretString, strlen(secretString), t, 15);
  for (int i = 1; i < r; i+=2) {
    char * key = (char *)calloc((t[i].end - t[i].start - 4), sizeof(char));
    char * val = (char *)calloc((t[i+1].end - t[i+1].start - 4), sizeof(char));
    sprintf(key, "%.*s", t[i].end - t[i].start - 4, secretString + 2 + t[i].start);
    sprintf(val, "%.*s", t[i+1].end - t[i+1].start - 4, secretString + 2 + t[i+1].start);
    setenv(key, val, 1);
    free(key);
    free(val);
  }

  system(command);

	return 0;
}
