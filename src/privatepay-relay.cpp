#include "privatepay.h"
#include "privatepay-relay.h"
#include "messagesigner.h"

CPrivatePayRelay::CPrivatePayRelay()
{
    vinMasternode = CTxIn();
    nBlockHeight = 0;
    nRelayType = 0;
    in = CTxIn();
    out = CTxOut();
}

CPrivatePayRelay::CPrivatePayRelay(CTxIn& vinMasternodeIn, vector<unsigned char>& vchSigIn, int nBlockHeightIn, int nRelayTypeIn, CTxIn& in2, CTxOut& out2)
{
    vinMasternode = vinMasternodeIn;
    vchSig = vchSigIn;
    nBlockHeight = nBlockHeightIn;
    nRelayType = nRelayTypeIn;
    in = in2;
    out = out2;
}

std::string CPrivatePayRelay::ToString()
{
    std::ostringstream info;

    info << "vin: " << vinMasternode.ToString() <<
        " nBlockHeight: " << (int)nBlockHeight <<
        " nRelayType: "  << (int)nRelayType <<
        " in " << in.ToString() <<
        " out " << out.ToString();
        
    return info.str();   
}

bool CPrivatePayRelay::Sign(std::string strSharedKey)
{
    std::string strError = "";
    std::string strMessage = in.ToString() + out.ToString();

    CKey key2;
    CPubKey pubkey2;

    if(!CMessageSigner::GetKeysFromSecret(strSharedKey, key2, pubkey2)) {
        LogPrintf("CPrivatePayRelay::Sign -- GetKeysFromSecret() failed, invalid shared key %s\n", strSharedKey);
        return false;
    }

    if(!CMessageSigner::SignMessage(strMessage, vchSig2, key2)) {
        LogPrintf("CPrivatePayRelay::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubkey2, vchSig2, strMessage, strError)) {
        LogPrintf("CPrivatePayRelay::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CPrivatePayRelay::VerifyMessage(std::string strSharedKey)
{
    std::string strError = "";
    std::string strMessage = in.ToString() + out.ToString();

    CKey key2;
    CPubKey pubkey2;

    if(!CMessageSigner::GetKeysFromSecret(strSharedKey, key2, pubkey2)) {
        LogPrintf("CPrivatePayRelay::VerifyMessage -- GetKeysFromSecret() failed, invalid shared key %s\n", strSharedKey);
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubkey2, vchSig2, strMessage, strError)) {
        LogPrintf("CPrivatePayRelay::VerifyMessage -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

void CPrivatePayRelay::Relay()
{
    int nCount = std::min(mnodeman.CountEnabled(MIN_PRIVATEPAY_PEER_PROTO_VERSION), 20);
    int nRank1 = (rand() % nCount)+1; 
    int nRank2 = (rand() % nCount)+1; 

    //keep picking another second number till we get one that doesn't match
    while(nRank1 == nRank2) nRank2 = (rand() % nCount)+1;

    //printf("rank 1 - rank2 %d %d \n", nRank1, nRank2);

    //relay this message through 2 separate nodes for redundancy
    RelayThroughNode(nRank1);
    RelayThroughNode(nRank2);
}

void CPrivatePayRelay::RelayThroughNode(int nRank)
{
    CMasternode* pmn = mnodeman.GetMasternodeByRank(nRank, nBlockHeight, MIN_PRIVATEPAY_PEER_PROTO_VERSION);

    if(pmn != NULL){
        //printf("RelayThroughNode %s\n", pmn->addr.ToString().c_str());
        // TODO: Pass CConnman instance somehow and don't use global variable.
        CNode* pnode = g_connman->ConnectNode((CAddress)pmn->addr, NULL);
        if(pnode) {
            //printf("Connected\n");
            pnode->PushMessage("dsr", (*this));
            return;
        }
    } else {
        //printf("RelayThroughNode NULL\n");
    }
}
