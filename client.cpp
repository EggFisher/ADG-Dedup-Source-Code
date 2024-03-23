#include <iostream>
#include "server.cpp"
#include "KSC.cpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <unordered_map>
using namespace std;

const streamsize BUFFER_SIZE = 1024 * 1024;  // 1MB buffer size
const int numShares = 5;
const int threshold=5;
const int blockSize=200*1024*1024;
const string ivString = "0123456789012345"; // AES-CBC 需要 16 字节长的 IV

class Client{
    string fileTag;
    string fileContent;
    string filePath;
    Server server;
    KSC ksc[numShares];
    vector<string> fileBlocks;
    BN_CTX* ctx;
    BIGNUM* prime;
    string aesKey;

    public:
    Client();
    bool fileUpload();
    int fileLevelDedup();
    string sha1(const string& fileContent);
    string readFileInChunks(const string &filePath);
    int majorityVoting();
    void dedupUnpopData();
    void dedupPopData();
    vector<string> splitStringIntoBlocks(const string& inputString);
    string md5(const string& input);
    void dedupPopSwitchData();
    string aesEncrypt(const string &plaintext, const string &keyString, const string &ivString);
    vector<pair<BIGNUM*, BIGNUM*>> splitSecret(BN_CTX* ctx, const BIGNUM* secret, int threshold, int numShares, const BIGNUM* prime);
    BIGNUM* generateRandomBignum(BN_CTX* ctx, const BIGNUM* modulus);
    BIGNUM* evaluatePolynomial(BN_CTX* ctx, const vector<BIGNUM*>& coeffs, const BIGNUM* x, const BIGNUM* prime);
    void handleErrors();
    string sha256(const string str);
    void blockLevelDedup();
    void processDuplicateBlocks(string blockPlaintext);
    void processNewBlocks(string blockPlaintext);
    string generateRandomAESKey();
};

int main(){
    Client client;
    if(client.fileUpload())
    {
        //重复文件
        int realNumF=client.fileLevelDedup();
        if(realNumF<threshold)
        {
            client.dedupUnpopData();
        }
        else if(realNumF==threshold)
        {
            client.dedupPopSwitchData();
        }
        else
        {
            client.dedupPopData();
        }
    }
    else
    {
        client.blockLevelDedup();
    }

    return 0;
}

Client::Client(){
    OpenSSL_add_all_algorithms();
    ctx = BN_CTX_new();

    // Generate a prime number of sufficient size
    prime = BN_new();
    BN_generate_prime_ex(prime, 256, 1, nullptr, nullptr, nullptr);

    filePath="file.txt";
}

bool Client::fileUpload(){
    //读取文件内容
    cout<<filePath<<":"<<endl;
    fileContent = readFileInChunks(filePath);

    //计算文件标签
    fileTag=sha1(fileContent);

    return server.checkDuplicate(fileTag);
}

int Client::majorityVoting(){
    unordered_map<int,int> mp;
    int maxCnt=0,maxAns;

    for(int i=0;i<numShares;++i){
        int numF=ksc[i].getNumF();

        mp[numF]++;

        if(mp[numF]>maxCnt) maxCnt=mp[numF],maxAns=numF;
    }
    return maxAns;
}

void Client::dedupPopSwitchData()
{
    vector<string> fileBlocks = splitStringIntoBlocks(fileContent);
    string conKey, blockCiphertext;

    //计算每一个文件块的密文和密钥
    for(auto ele:fileBlocks)
    {
        conKey = md5(ele);
        blockCiphertext = aesEncrypt(ele,conKey,ivString);

        string blockTag=sha1(ele);
        string PoWB=sha256(ele);
        server.storeBlockCiphertext(blockTag,PoWB,blockCiphertext);

        //重新计算KSC存储的密钥
	    string secretKey = conKey;
	    BIGNUM* secret = BN_bin2bn(reinterpret_cast<const unsigned char*>(secretKey.c_str()), secretKey.length(), nullptr);

	    vector<pair<BIGNUM*, BIGNUM*>> shares = splitSecret(ctx, secret, threshold, numShares, prime);
        for(int j=0;j<numShares;++j){
            string blockTagKSC=sha256(fileContent+to_string(j+1));
            ksc[j].storeBlockKeyKSC(blockTagKSC, shares[j]);
        }
    }
}

vector<pair<BIGNUM*, BIGNUM*>> Client::splitSecret(BN_CTX* ctx, const BIGNUM* secret, int threshold, int numShares, const BIGNUM* prime) {
    vector<BIGNUM*> coeffs(threshold);
    vector<pair<BIGNUM*, BIGNUM*>> shares(numShares);

    // Generate random coefficients for the polynomial
    for (int i = 0; i < threshold; ++i) {
        coeffs[i] = generateRandomBignum(ctx, prime);
    }

    // Evaluate the polynomial at x=1,2,...,numShares to generate shares
    for (int i = 0; i < numShares; ++i) {
        BIGNUM* x = BN_new();
        BN_set_word(x, i + 1); // Start x from 1
        BIGNUM* y = evaluatePolynomial(ctx, coeffs, x, prime);
        shares[i] = make_pair(x, y);
    }

    // Cleanup
    for (auto& coeff : coeffs) {
        BN_free(coeff);
    }

    return shares;
}

BIGNUM* Client::generateRandomBignum(BN_CTX* ctx, const BIGNUM* modulus) {
    BIGNUM* random = BN_new();
    BN_rand_range(random, modulus);
    return random;
}

BIGNUM* Client::evaluatePolynomial(BN_CTX* ctx, const vector<BIGNUM*>& coeffs, const BIGNUM* x, const BIGNUM* prime) {
    BIGNUM* result = BN_new();
    BN_set_word(result, 0);

    // Evaluate the polynomial using Horner's method
    for (int i = coeffs.size() - 1; i >= 0; --i) {
        BN_mod_mul(result, result, x, prime, ctx); // result = result * x mod prime
        BN_mod_add(result, result, coeffs[i], prime, ctx); // result = result + coeff[i] mod prime
    }

    return result;
}

void Client::dedupPopData()
{
    fileBlocks = splitStringIntoBlocks(fileContent);

    //计算每一个文件块的CK
    for(auto ele:fileBlocks)
    {
        string conKey = md5(ele);
    }
}

void Client::dedupUnpopData()
{
    for(int i=0;i<numShares;++i){
        ksc[i].getFileKeyKSC();
    }
}

void Client::blockLevelDedup(){
    //对文件进行分块
    vector<string> fileBlocks = splitStringIntoBlocks(fileContent);

    //为KSC生成文件标签
    for(int j=1;j<=numShares;++j){
        string fileTagSKC=sha256(fileContent+to_string(j));
        ksc[j-1].storeFileTagKSC(fileTagSKC);
        ksc[j-1].initNumF();
    }

    //CSP存储文件标签
    server.storeFileTag(fileTag);

    for(auto ele:fileBlocks){
        string blockTag = sha1(ele);

        if(server.checkDuplicate(blockTag)){
            processDuplicateBlocks(ele);
        }else{
            processNewBlocks(ele);
        }
    }
}

//处理重复块
void Client::processDuplicateBlocks(string blockPlaintext)
{
	string PoWB = sha256(blockPlaintext);

    if(!server.passPow(PoWB)){
        cout<<"Client did not pass PoW!"<<endl;
        exit(0);
    }else{
        server.getBlockCiphertext();
    }

	//对每个 KSC 计算 Tag_j(B_i) 进行 PoW_B,j
	for(int j = 1; j<=numShares; ++j ){
		string blockTagKSC = sha256(blockPlaintext + to_string(j));
        
        if(ksc[j-1].passPoW(blockTagKSC)){
            ksc[j-1].getBlockKeyKSC();
        }else{
            cout<<"Client did not pass PoW!"<<endl;
        }
	}
}

//处理新块
void Client::processNewBlocks(string blockPlaintext)
{
	//生成随机密钥
	aesKey = generateRandomAESKey();

	if(!aesKey.empty()){
		cout<<"aesKey:"<<aesKey<<endl;
	}else{
		cout<<"Failed to generate AES key"<<endl;
	}

	//加密
	string blockCiphertext = aesEncrypt(blockPlaintext, aesKey, ivString);
    string blockTag=sha1(blockPlaintext);
    string PoWB=sha256(blockPlaintext);
    server.storeBlockCiphertext(blockTag,PoWB,blockCiphertext);
    server.getBlockCiphertext();

    server.storeBlockTag(blockTag);

	//对每个 KSC 计算 Tag_j(B_i) 
	for(int j = 1;j <= numShares; ++j )
	{
		string blockTagKSC = sha256(blockPlaintext + to_string(j));
        ksc[j-1].storeBlockTagKSC(blockTagKSC);
	}

	//对每个 KSC 计算 K_ij
  	string secretKey = aesKey;
	BIGNUM* secret = BN_bin2bn(reinterpret_cast<const unsigned char*>(secretKey.c_str()), secretKey.length(), nullptr);

	vector<pair<BIGNUM*, BIGNUM*>> shares = splitSecret(ctx, secret, threshold, numShares, prime);
	for(int i=0;i<numShares;++i){
        string blockTagKSC=sha256(blockPlaintext+to_string(i+1));
        ksc[i].storeBlockKeyKSC(blockTagKSC,shares[i]);
        ksc[i].getBlockKeyKSC();
    }
}

int Client::fileLevelDedup(){
    //与CSP进行PoW
    string PoWF = sha256(fileContent);

    if(server.passPow(PoWF)){
        server.getFileCiphertext();
    }else{
        printf("Error! The user did not pass the PoW\n");
    }

    for(int j=1;j<=numShares;++j){
        string fileTagKSC = sha256(fileContent + to_string(j));
        if(ksc[j-1].passPoW(fileTagKSC)){
            ksc[j-1].addNumF();
        }
    }

    return majorityVoting();
}

string Client::sha256(const string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for(unsigned char i : hash) {
        ss << hex << setw(2) << setfill('0') << (int)i;
    }
    return ss.str();
}

//从文件路径下读取文件内容
string Client::readFileInChunks(const string &filePath) {
    ifstream inputFile(filePath, ios::binary);

    if (!inputFile.is_open()) {
        cerr << "Error opening file: " << filePath << endl;
        return "";
    }

    vector<char> buffer(BUFFER_SIZE);
    string fileContent;

    while (!inputFile.eof()) {
        inputFile.read(buffer.data(), buffer.size());
        fileContent.append(buffer.data(), static_cast<size_t>(inputFile.gcount()));
    }

    inputFile.close();

    return fileContent;
}

string Client::sha1(const string& fileContent) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned int md_len;

    mdctx = EVP_MD_CTX_new();

    md = EVP_sha1();
    EVP_DigestInit_ex(mdctx, md, NULL);

    EVP_DigestUpdate(mdctx, fileContent.c_str(), fileContent.length());

    EVP_DigestFinal_ex(mdctx, hash, &md_len);

    EVP_MD_CTX_free(mdctx);

    string result;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        char buf[3];
        sprintf(buf, "%02x", hash[i]);
        result += buf;
    }

    return result;
}

vector<string> Client::splitStringIntoBlocks(const string& inputString) {
    vector<string> blocks;

    // 遍历字符串
    for (size_t i = 0; i < inputString.length(); i += blockSize) {
        // 获取当前块
        string block = inputString.substr(i, blockSize);

        // 将当前块添加到数组或列表
        blocks.push_back(block);
    }

    return blocks;
}

string Client::md5(const string& input) 
{
    unsigned char md5Digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), md5Digest);

    string md5Hash;
    char hexDigest[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hexDigest + (i * 2), "%02x", md5Digest[i]);
    }
    hexDigest[MD5_DIGEST_LENGTH * 2] = '\0';
    md5Hash = hexDigest;

    return md5Hash;
}

void Client::handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

string Client::aesEncrypt(const string &plaintext, const string &keyString, const string &ivString) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    string ciphertext;

    unsigned char *key = reinterpret_cast<unsigned char*>(const_cast<char*>(keyString.data()));
    unsigned char *iv = reinterpret_cast<unsigned char*>(const_cast<char*>(ivString.data()));

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
        return "";
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    if(1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                              reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size())) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len)) {
        handleErrors();
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// 生成随机的AES加密密钥
string Client::generateRandomAESKey() 
{
    // Buffer to store random bytes
    unsigned char key[32];

    // Generate random bytes
    if (RAND_bytes(key, sizeof(key)) != 1) {
        // Handle error
        cerr << "Error generating random bytes: ";
        ERR_print_errors_fp(stderr);
        // Return empty string indicating failure
        return "";
    }

    // Convert random bytes to hexadecimal string
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < sizeof(key); ++i) {
        ss << setw(2) << static_cast<unsigned int>(key[i]);
    }

    return ss.str();
}
