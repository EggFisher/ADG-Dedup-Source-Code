#include <iostream>
#include <vector>
using namespace std;

class Server{
    private:
        struct serverFileLevelNode{
            string fileTag;
            string PoWF;
            vector<string*> fileCiphertextPointer;
        };
        serverFileLevelNode node1;

        struct serverBlockLevelNode{
            string blockTag;
            string PoWB;
            string blockCiphertext;
        };
        serverBlockLevelNode node2;

    public:
        bool checkDuplicate(string fileTag);
        bool passPow(string PoWTag);
        void storeBlockCiphertext(string blockTag, string PoWB, string cipher);
        string* getBlockCiphertext();
        vector<string*>* getFileCiphertext();
        void storeFileTag(string fileTag);
        void storeBlockTag(string blockTag);
};

//存储数据块密文
void Server::storeBlockCiphertext(string blockTag, string PoWB, string cipher){
    serverBlockLevelNode tmp;
    tmp.blockCiphertext=cipher;
    tmp.blockTag=blockTag;
    tmp.PoWB=PoWB;

    node1.fileCiphertextPointer.push_back(&tmp.blockCiphertext);
}

//存储文件标签
void Server::storeFileTag(string fileTag){
    node1.fileTag=fileTag;
}

//存储数据块标签
void Server::storeBlockTag(string blockTag){
    node2.blockTag=blockTag;
}

//获取文件密文
vector<string*>* Server::getFileCiphertext(){
    return &node1.fileCiphertextPointer;
}

//获取数据块密文
string* Server::getBlockCiphertext(){
    return &node2.blockCiphertext;
}

//检测是否重复
bool Server::checkDuplicate(string fileTag){

    return false;
}

bool Server::passPow(string PowTag){
    return true;
}

