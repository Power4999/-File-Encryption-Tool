#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define BLKSZ 16  
#define BUF 1024  

unsigned char key[] = "0123456789abcdef";  
unsigned char iv[16] = {0};  

// functions declaration
int do_encrypt(char* f);
int do_decrypt(char* f);

int fexists(char* p);
void enc_buf(unsigned char* in, int ilen, unsigned char* out, int* olen);
void dec_buf(unsigned char* in, int ilen, unsigned char* out, int* olen);

int main(int ac, char* av[]) {
    if(ac != 3) {
        printf("Usage: %s <encrypt|decrypt> <filename>\n", av[0]);
        return 1;
    }
 
    printf("\n");
    
    char* cmd = av[1];
    char* fn = av[2];
    
    if(!fexists(fn)) {
        printf("Can't find %s\n", fn);
        return 1;
    }
    
    int rc = 1;
   
    if(!strcmp(cmd, "encrypt")) {
        printf("Encrypting %s...\n", fn);
        rc = do_encrypt(fn);
    } else if(!strcmp(cmd, "decrypt")) {
        printf("Decrypting %s...\n", fn);
        rc = do_decrypt(fn);
    } else {
        printf("Unknown command: %s\n", cmd);
        printf("Usage: %s <encrypt|decrypt> <filename>\n", av[0]);
    }
    
    printf(rc ? "FAILED!\n" : "Success!\n");
    return rc;
}

int fexists(char* p) {
    FILE* f = fopen(p, "r");
    if(f) {
        fclose(f);
        return 1;
    }
    return 0;
}

int do_encrypt(char* f) {
    FILE *in, *out;
    char tmpf[100];
    unsigned char *ibuf, *obuf;
    int fsz, outsz;
    
    sprintf(tmpf, "%s.enc.tmp", f);
    
    in = fopen(f, "rb");
    if(!in) return 1;
    
    out = fopen(tmpf, "wb");
    if(!out) {
        fclose(in);
        return 1;
    }
    
    fseek(in, 0, SEEK_END);
    fsz = ftell(in);
    rewind(in);
    
    if(fsz <= 0 || fsz > 50*1024*1024) { 
        printf("Bad file size: %d\n", fsz);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    ibuf = malloc(fsz);
    if(!ibuf) {
        printf("No mem\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    
    obuf = malloc(fsz + BLKSZ);
    if(!obuf) {
        printf("No mem\n");
        free(ibuf);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    if(fread(ibuf, 1, fsz, in) != fsz) {
        printf("Read failed\n");
        free(ibuf); free(obuf);
        fclose(in); fclose(out);
        return 1;
    }
    
    enc_buf(ibuf, fsz, obuf, &outsz); 
    
    if(outsz <= 0) {
        printf("Enc failed\n");
        free(ibuf); free(obuf);
        fclose(in); fclose(out);
        return 1;
    }
    
    if(fwrite(obuf, 1, outsz, out) != outsz) {
        printf("Write failed\n");
        free(ibuf); free(obuf);
        fclose(in); fclose(out);
        remove(tmpf);
        return 1;
    }
    
    free(ibuf); free(obuf);
    fclose(in); fclose(out);
    
    remove(f);
    rename(tmpf, f);
    
    return 0;
}

int do_decrypt(char* f)
{
    FILE *in, *out;
    unsigned char *ibuf, *obuf; 
    int sz, osz;
    char tmp[100];
    
    sprintf(tmp, "%s.dec.tmp", f);
    
    if(!(in = fopen(f, "rb"))) 
        return 1;
    
    if(!(out = fopen(tmp, "wb"))) {
        printf("Cant create tmp file\n");
        fclose(in);
        return 1;
    }
    
    fseek(in, 0, SEEK_END);
    sz = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    ibuf = malloc(sz);
    obuf = malloc(sz); 
    
    if(!ibuf || !obuf) {
        printf("Out of memory\n");
        if(ibuf) free(ibuf);
        if(obuf) free(obuf);
        fclose(in);
        fclose(out);
        remove(tmp);
        return 1;
    }
    
    if(fread(ibuf, 1, sz, in) != sz) {
err:
        printf("IO error\n");
        free(ibuf); free(obuf);
        fclose(in); fclose(out);
        remove(tmp);
        return 1;
    }
    
    dec_buf(ibuf, sz, obuf, &osz);
    
    if(osz <= 0) {
        printf("Decryption failed - corrupt data or wrong key\n");
        free(ibuf); free(obuf);
        fclose(in); fclose(out);
        remove(tmp);
        return 1;
    }
    
    if(fwrite(obuf, 1, osz, out) != osz)
        goto err; 
    
    free(ibuf); free(obuf);
    fclose(in); fclose(out);
    
    remove(f);
    rename(tmp, f);
    
    return 0;
}

void enc_buf(unsigned char* in, int ilen, unsigned char* out, int* olen) {
    EVP_CIPHER_CTX* ctx;
    int len, clen=0;
    
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) { 
        *olen = 0; 
        return; 
    }
    
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        goto err;
    
    if(EVP_EncryptUpdate(ctx, out, &len, in, ilen) != 1)
        goto err;
    
    clen = len;
    
    if(EVP_EncryptFinal_ex(ctx, out+len, &len) != 1)
        goto err;
    
    clen += len;
    *olen = clen;
    EVP_CIPHER_CTX_free(ctx);
    return;
    
err:
    *olen = 0;
    EVP_CIPHER_CTX_free(ctx);
}

void dec_buf(unsigned char* in, int ilen, unsigned char* out, int* olen) {
    EVP_CIPHER_CTX* ctx;
    int len, plen=0;
    
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) { 
        *olen = 0; 
        return; 
    }
    
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        *olen = 0;
        return;
    }
    
    if(!EVP_DecryptUpdate(ctx, out, &len, in, ilen)) {
        EVP_CIPHER_CTX_free(ctx);
        *olen = 0;
        return;
    }
    
    plen = len;

    if(!EVP_DecryptFinal_ex(ctx, out+len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        *olen = 0;
        return;
    }
    
    plen += len;
    *olen = plen;
    
    EVP_CIPHER_CTX_free(ctx);
}
