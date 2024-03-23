#include <iostream>
#include <openssl/bn.h>
#include <vector>
using namespace std;

class KSC{
    private:
        struct KSCFileLevelNode{
            string fileTagKSC;
            int numF;
            vector<pair<BIGNUM*,BIGNUM*>*> fileKeyKSCPointer;
        };
        KSCFileLevelNode node1;

        struct KSCBlockLevelNode{
            string blockTagKSC;
            pair<BIGNUM*,BIGNUM*> blockKeyKSC;
        };
        KSCBlockLevelNode node2;

    public:
        bool passPoW(string PoWTag);
        vector<pair<BIGNUM*,BIGNUM*>*> getFileKeyKSC();
        void storeFileTagKSC(string fileTag);
        void storeBlockTagKSC(string blockTag);
        void addNumF();
        void storeBlockKeyKSC(string blockTag, pair<BIGNUM*,BIGNUM*> s);
        int getNumF();
        void initNumF();
        pair<BIGNUM*,BIGNUM*>* getBlockKeyKSC();
};

//存储数据块密钥
void KSC::storeBlockKeyKSC(string blockTag, pair<BIGNUM*,BIGNUM*> s){
    KSCBlockLevelNode tmp;
    tmp.blockTagKSC=blockTag;
    tmp.blockKeyKSC=s;
    node1.fileKeyKSCPointer.push_back(&tmp.blockKeyKSC);
}

//存储数据块标签 PoWB
void KSC::storeBlockTagKSC(string blockTag){
    node2.blockTagKSC=blockTag;
}

//存储文件标签
void KSC::storeFileTagKSC(string fileTag){
    node1.fileTagKSC=fileTag;
}

//获取数据块密钥
pair<BIGNUM*,BIGNUM*>* KSC::getBlockKeyKSC(){
    return &node2.blockKeyKSC;
}

//获取文件密钥
vector<pair<BIGNUM*,BIGNUM*>*> KSC::getFileKeyKSC(){
    return node1.fileKeyKSCPointer;
}

bool KSC::passPoW(string PoWTag){
    return true;
}

void KSC::initNumF(){
    node1.numF=1;
}

void KSC::addNumF(){
    node1.numF++;
}

int KSC::getNumF(){
    return node1.numF;
}