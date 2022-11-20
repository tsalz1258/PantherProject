// Server side C/C++ program to demonstrate Socket
// programming
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <gcrypt.h>

  char* Passchecker(char * password){// checks if the password is correct.
  gcry_error_t err;

  size_t key_size = 64;
  char key[key_size];
  err = gcry_kdf_derive(password, strlen(password),
  GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
  "NaCl", 4,
  4096,
  key_size, key);
  if (err)
  {
    printf("something failed:  %s/%s\n",
           gcry_strsource(err),
           gcry_strerror(err));
  }
  int i, j = 0;
  char hexstr[(strlen(key)*2)];
  for (i = 0; i < 65; i++)
  {
      char c = key[i];
      int checker = (int)(c);
      if(checker < 0){
      checker = checker + 256;} // some values reutrn negative, this checks and makes them postive for a proper key
      sprintf(hexstr + j, "%02X", checker);// turns values into hex
      j += 2;
  }
  hexstr[strlen(hexstr)- 2] = '\0'; //adds null terminater at the end of the char array

 char *passcheck = (char *)malloc(strlen(hexstr)+1);
 strcpy(passcheck,hexstr);
return passcheck;
}



int main(int argc, char const* argv[])
{
  char * messageEnc;
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = { 0 }; //what stores the message that is sent over from the Client
    char * password = malloc(128);
if(!strcmp(argv[2],"-d")){
    printf("Waiting for a connection\n");
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0))
        == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(strtol(argv[3], NULL,10));

    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address))
        < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket
         = accept(server_fd, (struct sockaddr*)&address,
                  (socklen_t*)&addrlen))
        < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    printf("Inbound file.\n");

    valread = read(new_socket, buffer, 1500);// takes value from the client
    close(new_socket);

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket
         = accept(server_fd, (struct sockaddr*)&address,
                  (socklen_t*)&addrlen))
        < 0) {
        perror("accept");
        exit(EXIT_FAILURE);}
        valread = read(new_socket, password, 1500); //gets the password from the client

      close(new_socket);
      close(new_socket);

    // closing the connected socket
    // closing the listening socket
    shutdown(server_fd, SHUT_RDWR);

    printf("key: ");
    for(int i = 0; i <= strlen(password)-2; i = i + 2){
      printf("%c%c ", password[i], password[i+1]);
    }
    char *userPass = malloc(30);
    printf("\nPlease enter a password:");
    scanf("%s",userPass);

    if(!strcmp(password,Passchecker(userPass))){
      printf("Password is correct!");
     }
     else{
       printf("Password is incorrect, Exiting program ");
       return 0;
     }
    free(userPass);
}
else if(!strcmp(argv[2],"-l")){ // if -l is given, will decrypt locally
FILE *fp;
char * filename = malloc(20);
strcpy(filename,argv[1]);
fp = fopen(filename,"r+");
messageEnc  = malloc(200); // buffer will hold the encrypted message
while(fgets(buffer, 64, fp) != NULL){ //gets contents from the file
  strcat(messageEnc,buffer);
}

fclose(fp);
free(filename);
}
    gcry_cipher_hd_t handle;
    gcry_error_t err;
    gcry_md_hd_t mdhandle;

    size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128);
    char * aesSymKey = "one test AES key";
    size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128);
    char * HmacCHecker;
//-------------------------------------------------------------------------
if(!strcmp(argv[2],"-d")){ // network choice for Hmac
  char * Hmac = malloc(65);
 messageEnc = malloc(strlen(buffer) - 65);
 strncpy(Hmac, &buffer[strlen(buffer)-65],65);// gets the last 65 bytes of the message which is the Hmac
 strncpy(messageEnc, &buffer[0],strlen(buffer)-65);
err = gcry_md_open(&mdhandle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
if(err){
  printf("hash open failed has failled: %s/%s\n",
          gcry_strsource(err),
          gcry_strerror(err));
}
err =gcry_md_setkey(mdhandle, aesSymKey, keyLength);
if (err)
   {
       printf("gcry_md_setkey failed:  %s/%s\n",
              gcry_strsource(err),
              gcry_strerror(err));
   }
gcry_md_write(mdhandle, messageEnc, strlen(messageEnc));
HmacCHecker = gcry_md_read(mdhandle, GCRY_MD_SHA512);

if(!strcmp(HmacCHecker, Hmac)){
  printf("\nHmac Successfully verifed!\n");
}
else{
  printf("Hmac incorrect! Terrminating program!\nError Code: 62\n");
  return 62;
}
free(Hmac);
}
size_t decodeSIZE = strlen(messageEnc);
char * DecodeMessage = malloc(decodeSIZE);
//---------------------------------------------------------------------
    // int iv_vector = 5844;
    // const void *iv = &iv_vector;
    err = gcry_cipher_open (&handle, GCRY_CIPHER_AES128,
    GCRY_CIPHER_MODE_CBC, 0);
    err =gcry_cipher_setkey(handle, aesSymKey, keyLength);
    if (err)
       {
           printf("gcry_cipher_setkey failed:  %s/%s\n",
                  gcry_strsource(err),
                  gcry_strerror(err));
       }
       char * iv = "a test ini value";;
    err = gcry_cipher_setiv(handle, iv, blkLength);
    if (err)
        {
            printf("gcry_cipher_setiv failed:  %s/%s\n",
                   gcry_strsource(err),
                   gcry_strerror(err));
        }
    err = gcry_cipher_decrypt(handle, DecodeMessage, decodeSIZE, messageEnc,decodeSIZE); //decrypt messages and stores it into DecodeMessage
    if(err){
      printf("Decode has failled: %s/%s\n",
              gcry_strsource(err),
              gcry_strerror(err));}

              int i, j;
                  int len = strlen(DecodeMessage); // this loop takes out any charcters that do not belong in the original message.
                  for(i=0; i<len; i++)
                  {
                      if(DecodeMessage[i] == ':')
                      {
                          for(j=i; j<len; j++)
                          {
                              DecodeMessage[j] = ' ';
                          }
                          len--;
                          i--;
                      }
                  }
    char filex[strlen(argv[1])];
    strcpy(filex, argv[1]);

    char *match;
	  int exlen = strlen(".fiu");
	  while ((match = strstr(filex, ".fiu"))) { //checks if the extension is .fiu
		*match = '\0';
		strcat(filex, match+exlen);
	}

    printf("Successfully received and decryted file (%ld bytes written)\n", strlen(DecodeMessage));
    if( access( filex, F_OK ) != -1)
   {
     printf("ERROR CODE 33: Output file already exists\n");
      return 33;
   }
    FILE *fp;
    char * filename = malloc(25);
    strcpy(filename,argv[1]);
    fp = fopen(filex,"w");

    fprintf(fp,"%s", DecodeMessage);

    free(filename);
    fclose(fp);

    free(DecodeMessage);
    free(password);
    free(messageEnc);

    return 0;
}
