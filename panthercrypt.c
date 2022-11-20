#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#define GCRY_CIPHER GCRY_CIPHER_AES128 //selecting encrytion type as aes128
#define GCRY_MODE GCRY_CIPHER_MODE_CBC // selecting encrytion mode as CBC

int socketSend(char * buffer, char * address, char * port)
{


  int sock = 0, valread, client_fd;
  struct sockaddr_in serv_addr;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(strtol(port, NULL,10));

  // Convert IPv4 and IPv6 addresses from text to binary
  // form
  if (inet_pton(AF_INET, address, &serv_addr.sin_addr)
  <= 0) {
    printf(
      "\nInvalid address/ Address not supported \n");
      return -1;
    }

    if ((client_fd
      = connect(sock, (struct sockaddr*)&serv_addr,
      sizeof(serv_addr)))
      < 0) {
        printf("\nConnection Failed \n");
        return -1;
      }
      send(sock, buffer, strlen(buffer), 0);

      close(client_fd);
    }

int main(int argc, char *argv[] )
    {
      FILE* ptr;
      char * MessageBuffer = malloc(2048);
      ptr = fopen(argv[1], "r+");
      if (NULL == ptr) {
        printf("file can't be opened \n");
      }


      while (fgets(MessageBuffer, 2048, ptr) != NULL) {
      }
      fclose(ptr);

      gcry_check_version ( GCRYPT_VERSION );
      gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
      gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

      if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
      {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
      }

      char * passphrase = malloc(200);
      printf("password: ");
      scanf("%s", passphrase );


      gcry_cipher_hd_t handle;
      gcry_md_hd_t mdhandle;
      gcry_error_t err;
      size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
      size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);

      if(strlen(MessageBuffer) % 16){
        char *addspace = malloc(16);
        int newsize = strlen(MessageBuffer) % 16;
        newsize = 16 - newsize;

        MessageBuffer = (char *) realloc( MessageBuffer, strlen(MessageBuffer) + newsize);

        for(int i = 0; i<newsize; i++){
          strcat(addspace, ":");
        }
        strcat(MessageBuffer, addspace);
        free(addspace);
      }
      size_t MessageLength = strlen(MessageBuffer);
      char * encMessage = malloc(MessageLength);
      char * iv = "a test ini value";
      char * aesSymKey = "one test AES key";
      char * hashbuff;
      err = gcry_cipher_open (&handle, GCRY_CIPHER,
        GCRY_MODE, 0);


        err =gcry_cipher_setkey(handle, aesSymKey, keyLength);
        if (err)
        {
          printf("gcry_cipher_setkey failed:  %s/%s\n",
          gcry_strsource(err),
          gcry_strerror(err));
        }
        // int iv_vector = 5844;
        // const void *iv = &iv_vector;
        err =gcry_cipher_setiv(handle, iv, blkLength);
        if (err)
        {
          printf("gcry_cipher_setiv failed:  %s/%s\n",
          gcry_strsource(err),
          gcry_strerror(err));
        }
        err = gcry_cipher_encrypt(handle,encMessage,MessageLength, MessageBuffer, MessageLength);
        if(err){
          printf("gcry_cipher_encrypt failed:  %s/%s\n",
          gcry_strsource(err),
          gcry_strerror(err));
        }


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

        gcry_md_write(mdhandle, encMessage, MessageLength);


        hashbuff = gcry_md_read(mdhandle, GCRY_MD_SHA512);

        char FinalBuff [strlen(encMessage)+ 65];
        strcpy(FinalBuff,encMessage);
        strcat(FinalBuff, hashbuff);


        gcry_cipher_close(handle);


        //----------------------------------------------------------------

        size_t key_size = 64;
        char key[key_size];
        char *salt = "NaCl";
        err = gcry_kdf_derive(passphrase, strlen(passphrase),
        GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
        salt, strlen(salt),
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
            checker = checker + 256;}
            sprintf(hexstr + j, "%02X", checker);
            j += 2;
          }
          hexstr[strlen(hexstr)- 2] = '\0';
          printf("Key: ");
          for(int i = 0; i <= strlen(hexstr)-2; i = i + 2){
            printf("%c%c ", hexstr[i], hexstr[i+1]);
          }

          if(!strcmp(argv[2],"-d")){
            char * address = malloc(20);
            address = argv[3];
            char * port = malloc(6);
            char *match;
            int len = strlen(":");
            while ((match = strstr(address, ":"))) {
              strcpy(port, match);
              *match = '\0';
              port = port +1;

            }
            socketSend(FinalBuff,address,port);
            socketSend(hexstr,address,port);
            printf("\nTransmitting to %s:%s\n", address, port);
          }
          else if(!strcmp(argv[2],"-l")){
            FILE *fp;
            char * filename = argv[1];
            strcat(filename, ".fiu");
            fp = fopen(filename,"w+");
            fprintf(fp, "%s", encMessage);

            fclose(fp);

          }

          free(passphrase);
          free(MessageBuffer);
          printf("\nSuccessfully encrpyted %s to %s.fiu (%ld bytes written)",argv[1], argv[1], strlen(FinalBuff));
          free(encMessage);

          return 0;}
