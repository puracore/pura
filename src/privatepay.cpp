// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2017 The Pura Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "privatepay.h"

#include "activemasternode.h"
#include "consensus/validation.h"
#include "governance.h"
#include "init.h"
#include "instapay.h"
#include "masternode-payments.h"
#include "masternode-sync.h"
#include "masternodeman.h"
#include "messagesigner.h"
#include "script/sign.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"

#include <boost/lexical_cast.hpp>

CPrivatePayEntry::CPrivatePayEntry(const std::vector<CTxIn>& vecTxIn, const std::vector<CTxOut>& vecTxOut, const CTransaction& txCollateral) :
    txCollateral(txCollateral), addr(CService())
{
    BOOST_FOREACH(CTxIn txin, vecTxIn)
        vecTxDSIn.push_back(txin);
    BOOST_FOREACH(CTxOut txout, vecTxOut)
        vecTxDSOut.push_back(txout);
}

bool CPrivatePayEntry::AddScriptSig(const CTxIn& txin)
{
    BOOST_FOREACH(CTxDSIn& txdsin, vecTxDSIn) {
        if(txdsin.prevout == txin.prevout && txdsin.nSequence == txin.nSequence) {
            if(txdsin.fHasSig) return false;

            txdsin.scriptSig = txin.scriptSig;
            txdsin.prevPubKey = txin.prevPubKey;
            txdsin.fHasSig = true;

            return true;
        }
    }

    return false;
}

bool CPrivatepayQueue::Sign()
{
    if(!fMasterNode) return false;

    std::string strMessage = vin.ToString() + boost::lexical_cast<std::string>(nDenom) + boost::lexical_cast<std::string>(nTime) + boost::lexical_cast<std::string>(fReady);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, activeMasternode.keyMasternode)) {
        LogPrintf("CPrivatepayQueue::Sign -- SignMessage() failed, %s\n", ToString());
        return false;
    }

    return CheckSignature(activeMasternode.pubKeyMasternode);
}

bool CPrivatepayQueue::CheckSignature(const CPubKey& pubKeyMasternode)
{
    std::string strMessage = vin.ToString() + boost::lexical_cast<std::string>(nDenom) + boost::lexical_cast<std::string>(nTime) + boost::lexical_cast<std::string>(fReady);
    std::string strError = "";

    if(!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
        LogPrintf("CPrivatepayQueue::CheckSignature -- Got bad Masternode queue signature: %s; error: %s\n", ToString(), strError);
        return false;
    }

    return true;
}

bool CPrivatepayQueue::Relay()
{
    std::vector<CNode*> vNodesCopy = g_connman->CopyNodeVector();
    BOOST_FOREACH(CNode* pnode, vNodesCopy)
        if(pnode->nVersion >= MIN_PRIVATEPAY_PEER_PROTO_VERSION)
            g_connman->PushMessage(pnode, NetMsgType::PPQUEUE, (*this));

    g_connman->ReleaseNodeVector(vNodesCopy);
    return true;
}

bool CPrivatepayBroadcastTx::Sign()
{
    if(!fMasterNode) return false;

    std::string strMessage = tx.GetHash().ToString() + boost::lexical_cast<std::string>(sigTime);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, activeMasternode.keyMasternode)) {
        LogPrintf("CPrivatepayBroadcastTx::Sign -- SignMessage() failed\n");
        return false;
    }

    return CheckSignature(activeMasternode.pubKeyMasternode);
}

bool CPrivatepayBroadcastTx::CheckSignature(const CPubKey& pubKeyMasternode)
{
    std::string strMessage = tx.GetHash().ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string strError = "";

    if(!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
        LogPrintf("CPrivatepayBroadcastTx::CheckSignature -- Got bad pptx signature, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CPrivatepayBroadcastTx::IsExpired(int nHeight)
{
    // expire confirmed PPTXes after ~1h since confirmation
    return (nConfirmedHeight != -1) && (nHeight - nConfirmedHeight > 24);
}

void CPrivatePayBase::SetNull()
{
    // Both sides
    nState = POOL_STATE_IDLE;
    nSessionID = 0;
    nSessionDenom = 0;
    vecEntries.clear();
    finalMutableTransaction.vin.clear();
    finalMutableTransaction.vout.clear();
    nTimeLastSuccessfulStep = GetTimeMillis();
}

std::string CPrivatePayBase::GetStateString() const
{
    switch(nState) {
        case POOL_STATE_IDLE:                   return "IDLE";
        case POOL_STATE_QUEUE:                  return "QUEUE";
        case POOL_STATE_ACCEPTING_ENTRIES:      return "ACCEPTING_ENTRIES";
        case POOL_STATE_SIGNING:                return "SIGNING";
        case POOL_STATE_ERROR:                  return "ERROR";
        case POOL_STATE_SUCCESS:                return "SUCCESS";
        default:                                return "UNKNOWN";
    }
}

// Definitions for static data members
std::vector<CAmount> CPrivatePay::vecStandardDenominations;
std::map<uint256, CPrivatepayBroadcastTx> CPrivatePay::mapPPTX;
CCriticalSection CPrivatePay::cs_mappptx;

void CPrivatePay::InitStandardDenominations()
{
    vecStandardDenominations.clear();
    /* Denominations

        A note about convertability. Within mixing pools, each denomination
        is convertable to another.

        For example:
        1PURA+1000 == (.1PURA+100)*10
        10PURA+10000 == (1PURA+1000)*10
    */
    /* Disabled
    vecStandardDenominations.push_back( (100      * COIN)+100000 );
    */
    vecStandardDenominations.push_back( (10       * COIN)+10000 );
    vecStandardDenominations.push_back( (1        * COIN)+1000 );
    vecStandardDenominations.push_back( (.1       * COIN)+100 );
    vecStandardDenominations.push_back( (.01      * COIN)+10 );
    /* Disabled till we need them
    vecStandardDenominations.push_back( (.001     * COIN)+1 );
    */
}

// check to make sure the collateral provided by the client is valid
bool CPrivatePay::IsCollateralValid(const CTransaction& txCollateral)
{
    if(txCollateral.vout.empty()) return false;
    if(txCollateral.nLockTime != 0) return false;

    CAmount nValueIn = 0;
    CAmount nValueOut = 0;
    bool fMissingTx = false;

    BOOST_FOREACH(const CTxOut txout, txCollateral.vout) {
        nValueOut += txout.nValue;

        if(!txout.scriptPubKey.IsNormalPaymentScript()) {
            LogPrintf ("CPrivatePay::IsCollateralValid -- Invalid Script, txCollateral=%s", txCollateral.ToString());
            return false;
        }
    }

    BOOST_FOREACH(const CTxIn txin, txCollateral.vin) {
        CTransaction txPrev;
        uint256 hash;
        if(GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), hash, true)) {
            if(txPrev.vout.size() > txin.prevout.n)
                nValueIn += txPrev.vout[txin.prevout.n].nValue;
        } else {
            fMissingTx = true;
        }
    }

    if(fMissingTx) {
        LogPrint("privatepay", "CPrivatePay::IsCollateralValid -- Unknown inputs in collateral transaction, txCollateral=%s", txCollateral.ToString());
        return false;
    }

    //collateral transactions are required to pay out a small fee to the miners
    if(nValueIn - nValueOut < GetCollateralAmount()) {
        LogPrint("privatepay", "CPrivatePay::IsCollateralValid -- did not include enough fees in transaction: fees: %d, txCollateral=%s", nValueOut - nValueIn, txCollateral.ToString());
        return false;
    }

    LogPrint("privatepay", "CPrivatePay::IsCollateralValid -- %s", txCollateral.ToString());

    {
        LOCK(cs_main);
        CValidationState validationState;
        if(!AcceptToMemoryPool(mempool, validationState, txCollateral, false, NULL, false, true, true)) {
            LogPrint("privatepay", "CPrivatePay::IsCollateralValid -- didn't pass AcceptToMemoryPool()\n");
            return false;
        }
    }

    return true;
}

/*  Create a nice string to show the denominations
    Function returns as follows (for 4 denominations):
        ( bit on if present )
        bit 0           - 100
        bit 1           - 10
        bit 2           - 1
        bit 3           - .1
        bit 4 and so on - out-of-bounds
        none of above   - non-denom
*/
std::string CPrivatePay::GetDenominationsToString(int nDenom)
{
    std::string strDenom = "";
    int nMaxDenoms = vecStandardDenominations.size();

    if(nDenom >= (1 << nMaxDenoms)) {
        return "out-of-bounds";
    }

    for (int i = 0; i < nMaxDenoms; ++i) {
        if(nDenom & (1 << i)) {
            strDenom += (strDenom.empty() ? "" : "+") + FormatMoney(vecStandardDenominations[i]);
        }
    }

    if(strDenom.empty()) {
        return "non-denom";
    }

    return strDenom;
}

int CPrivatePay::GetDenominations(const std::vector<CTxDSOut>& vecTxDSOut)
{
    std::vector<CTxOut> vecTxOut;

    BOOST_FOREACH(CTxDSOut out, vecTxDSOut)
        vecTxOut.push_back(out);

    return GetDenominations(vecTxOut);
}

/*  Return a bitshifted integer representing the denominations in this list
    Function returns as follows (for 4 denominations):
        ( bit on if present )
        100       - bit 0
        10        - bit 1
        1         - bit 2
        .1        - bit 3
        non-denom - 0, all bits off
*/
int CPrivatePay::GetDenominations(const std::vector<CTxOut>& vecTxOut, bool fSingleRandomDenom)
{
    std::vector<std::pair<CAmount, int> > vecDenomUsed;

    // make a list of denominations, with zero uses
    BOOST_FOREACH(CAmount nDenomValue, vecStandardDenominations)
        vecDenomUsed.push_back(std::make_pair(nDenomValue, 0));

    // look for denominations and update uses to 1
    BOOST_FOREACH(CTxOut txout, vecTxOut) {
        bool found = false;
        BOOST_FOREACH (PAIRTYPE(CAmount, int)& s, vecDenomUsed) {
            if(txout.nValue == s.first) {
                s.second = 1;
                found = true;
            }
        }
        if(!found) return 0;
    }

    int nDenom = 0;
    int c = 0;
    // if the denomination is used, shift the bit on
    BOOST_FOREACH (PAIRTYPE(CAmount, int)& s, vecDenomUsed) {
        int bit = (fSingleRandomDenom ? GetRandInt(2) : 1) & s.second;
        nDenom |= bit << c++;
        if(fSingleRandomDenom && bit) break; // use just one random denomination
    }

    return nDenom;
}

bool CPrivatePay::GetDenominationsBits(int nDenom, std::vector<int> &vecBitsRet)
{
    // ( bit on if present, 4 denominations example )
    // bit 0 - 100PURA+1
    // bit 1 - 10PURA+1
    // bit 2 - 1PURA+1
    // bit 3 - .1PURA+1

    int nMaxDenoms = vecStandardDenominations.size();

    if(nDenom >= (1 << nMaxDenoms)) return false;

    vecBitsRet.clear();

    for (int i = 0; i < nMaxDenoms; ++i) {
        if(nDenom & (1 << i)) {
            vecBitsRet.push_back(i);
        }
    }

    return !vecBitsRet.empty();
}

int CPrivatePay::GetDenominationsByAmounts(const std::vector<CAmount>& vecAmount)
{
    CScript scriptTmp = CScript();
    std::vector<CTxOut> vecTxOut;

    BOOST_REVERSE_FOREACH(CAmount nAmount, vecAmount) {
        CTxOut txout(nAmount, scriptTmp);
        vecTxOut.push_back(txout);
    }

    return GetDenominations(vecTxOut, true);
}

std::string CPrivatePay::GetMessageByID(PoolMessage nMessageID)
{
    switch (nMessageID) {
        case ERR_ALREADY_HAVE:          return _("Already have that input.");
        case ERR_DENOM:                 return _("No matching denominations found for mixing.");
        case ERR_ENTRIES_FULL:          return _("Entries are full.");
        case ERR_EXISTING_TX:           return _("Not compatible with existing transactions.");
        case ERR_FEES:                  return _("Transaction fees are too high.");
        case ERR_INVALID_COLLATERAL:    return _("Collateral not valid.");
        case ERR_INVALID_INPUT:         return _("Input is not valid.");
        case ERR_INVALID_SCRIPT:        return _("Invalid script detected.");
        case ERR_INVALID_TX:            return _("Transaction not valid.");
        case ERR_MAXIMUM:               return _("Entry exceeds maximum size.");
        case ERR_MN_LIST:               return _("Not in the Masternode list.");
        case ERR_MODE:                  return _("Incompatible mode.");
        case ERR_NON_STANDARD_PUBKEY:   return _("Non-standard public key detected.");
        case ERR_NOT_A_MN:              return _("This is not a Masternode."); // not used
        case ERR_QUEUE_FULL:            return _("Masternode queue is full.");
        case ERR_RECENT:                return _("Last PrivatePay was too recent.");
        case ERR_SESSION:               return _("Session not complete!");
        case ERR_MISSING_TX:            return _("Missing input transaction information.");
        case ERR_VERSION:               return _("Incompatible version.");
        case MSG_NOERR:                 return _("No errors detected.");
        case MSG_SUCCESS:               return _("Transaction created successfully.");
        case MSG_ENTRIES_ADDED:         return _("Your entries added successfully.");
        default:                        return _("Unknown response.");
    }
}

void CPrivatePay::AddPPTX(const CPrivatepayBroadcastTx& pptx)
{
    LOCK(cs_mappptx);
    mapPPTX.insert(std::make_pair(pptx.tx.GetHash(), pptx));
}

CPrivatepayBroadcastTx CPrivatePay::GetPPTX(const uint256& hash)
{
    LOCK(cs_mappptx);
    auto it = mapPPTX.find(hash);
    return (it == mapPPTX.end()) ? CPrivatepayBroadcastTx() : it->second;
}

void CPrivatePay::CheckPPTXes(int nHeight)
{
    LOCK(cs_mappptx);
    std::map<uint256, CPrivatepayBroadcastTx>::iterator it = mapPPTX.begin();
    while(it != mapPPTX.end()) {
        if (it->second.IsExpired(nHeight)) {
            mapPPTX.erase(it++);
        } else {
            ++it;
        }
    }
    LogPrint("privatepay", "CPrivatePay::CheckPPTXes -- mapPPTX.size()=%llu\n", mapPPTX.size());
}

void CPrivatePay::SyncTransaction(const CTransaction& tx, const CBlock* pblock)
{
    if (tx.IsCoinBase()) return;

    LOCK2(cs_main, cs_mappptx);

    uint256 txHash = tx.GetHash();
    if (!mapPPTX.count(txHash)) return;

    // When tx is 0-confirmed or conflicted, pblock is NULL and nConfirmedHeight should be set to -1
    CBlockIndex* pblockindex = NULL;
    if(pblock) {
        uint256 blockHash = pblock->GetHash();
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if(mi == mapBlockIndex.end() || !mi->second) {
            // shouldn't happen
            LogPrint("privatepay", "CPrivatePayClient::SyncTransaction -- Failed to find block %s\n", blockHash.ToString());
            return;
        }
        pblockindex = mi->second;
    }
    mapPPTX[txHash].SetConfirmedHeight(pblockindex ? pblockindex->nHeight : -1);
    LogPrint("privatepay", "CPrivatePayClient::SyncTransaction -- txid=%s\n", txHash.ToString());
}

//TODO: Rename/move to core
void ThreadCheckPrivatePay()
{
    if(fLiteMode) return; // disable all Pura specific functionality

    static bool fOneThread;
    if(fOneThread) return;
    fOneThread = true;

    // Make this thread recognisable as the PrivatePay thread
    RenameThread("pura-ps");

    unsigned int nTick = 0;

    while (true)
    {
        MilliSleep(1000);

        // try to sync from all available nodes, one step at a time
        masternodeSync.ProcessTick();

        if(masternodeSync.IsBlockchainSynced() && !ShutdownRequested()) {

            nTick++;

            // make sure to check all masternodes first
            mnodeman.Check();

            // check if we should activate or ping every few minutes,
            // slightly postpone first run to give net thread a chance to connect to some peers
            if(nTick % MASTERNODE_MIN_MNP_SECONDS == 15)
                activeMasternode.ManageState();

            if(nTick % 60 == 0) {
                mnodeman.ProcessMasternodeConnections();
                mnodeman.CheckAndRemove();
                mnpayments.CheckAndRemove();
                instapay.CheckAndRemove();
            }
            if(fMasterNode && (nTick % (60 * 5) == 0)) {
                mnodeman.DoFullVerificationStep();
            }

            if(nTick % (60 * 5) == 0) {
                governance.DoMaintenance();
            }
        }
    }
}
