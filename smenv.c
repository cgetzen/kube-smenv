#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <curl/curl.h>

#include "sha.h"
#include "hmac.h"

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

struct MemoryStruct {
  char *memory;
  size_t size;
};

unsigned char* sign(const unsigned char* akey, const unsigned char* msg) {
	unsigned char* mac = (unsigned char*) malloc((SHA256_DIGEST_SIZE+1) * sizeof(unsigned char));
	mac[SHA256_DIGEST_SIZE] = 0;
	hmac_sha256(akey, strlen((char *)akey), msg, strlen((char *)msg), mac, SHA256_DIGEST_SIZE);
	return mac;
}

char* hex_dump(unsigned char* in) {
	char* ret = (char*) malloc(strlen((char *)in) * 2 * sizeof(char));
	for (int i = 0; i < strlen((char *)in); i++) {
		sprintf(ret+i+i, "%02x", *(in+i));
	}
	return ret;
}

unsigned char* getSignatureKey(const unsigned char* key, const unsigned char* date_stamp,
	const unsigned char* region_name, const unsigned char* service_name) {
		unsigned char* intermediate = (unsigned char*) malloc(600 * sizeof(unsigned char));
		strcpy( (char*) intermediate, "AWS4" );
		strcpy( (char*) intermediate+4, (char*) key);

		unsigned char* kDate = sign((unsigned char*)intermediate, date_stamp);
		unsigned char* kRegion = sign(kDate, region_name);
		unsigned char* kService = sign(kRegion, service_name);
		unsigned char* kSigning = sign(kService, (unsigned char *) "aws4_request");
		return kSigning;
}

char* hex_sha(const char* input) {
	unsigned char sha[300];
	sha256((const unsigned char*)input, strlen(input), (unsigned char *) sha);
	char* hex_dump = (char*) malloc(64 * sizeof(char));
	for (int i = 0; i < 32; i++) {
		sprintf(hex_dump+i+i, "%02x", *(sha+i));
	}
	return hex_dump;
}

int main2() {
	unsigned char key[]  =  "AWS4x/wpMs9iw5xPT6Dvo8u/402PofoBB6OW5o4Zm9zq";
	unsigned char date[] = "20190627";
	unsigned char* x = sign(key, date);
	printf("%d\n", x[0]);
	return 0;
}

int main3() {
	unsigned char one[] = {105, 117, 48, 57, 207, 155, 51, 211, 145, 74, 55, 252, 139, 223, 141, 197, 175, 23, 72, 203, 242, 58, 85, 230, 124, 167, 38, 15, 25, 138, 163, 234};
	unsigned char two[] = "us-east-1";
	unsigned char* x = sign(one, two);
	printf("%d\n", x[0]);
	return 0;
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

int main() {
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

	unsigned char * signing_key = getSignatureKey((unsigned char *)secret_key, (unsigned char *) date_stamp, (unsigned char *) region, (unsigned char *) service);
	unsigned char * signature = sign(signing_key, (unsigned char *) string_to_sign);
	char authorization_header[1000];
	sprintf(authorization_header, "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", algorithm, access_key, credential_scope, signed_headers, hex_dump(signature));

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

	return 0;
}
