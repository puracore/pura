// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2017 The Pura Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "privatepay-client.h"

#include "coincontrol.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "masternode-sync.h"
#include "masternodeman.h"
#include "script/sign.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"

#include <memory>

CPrivatePayClient privatePayClient;

void CPrivatePayClient::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if(fMasterNode) return;
    if(fLiteMode) return; // ignore all Pura related functionality
    if(!masternodeSync.IsBlockchainSynced()) return;

    if(strCommand == NetMsgType::PPQUEUE) {
        TRY_LOCK(cs_privatepay, lockRecv);
        if(!lockRecv) return;

        if(pfrom->nVersion < MIN_PRIVATEPAY_PEER_PROTO_VERSION) {
            LogPrint("privatepay", "PPQUEUE -- incompatible version! nVersion: %d\n", pfrom->nVersion);
            return;
        }

        CPrivatepayQueue dsq;
        vRecv >> dsq;

        // process every dsq only once
        BOOST_FOREACH(CPrivatepayQueue q, vecPrivatepayQueue) {
            if(q == dsq) {
                // LogPrint("privatepay", "PPQUEUE -- %s seen\n", dsq.ToString());
                return;
            }
        }

        LogPrint("privatepay", "PPQUEUE -- %s new\n", dsq.ToString());

        if(dsq.IsExpired() || dsq.nTime > GetTime() + PRIVATEPAY_QUEUE_TIMEOUT) return;

        masternode_info_t infoMn = mnodeman.GetMasternodeInfo(dsq.vin);
        if(!infoMn.fInfoValid) return;

        if(!dsq.CheckSignature(infoMn.pubKeyMasternode)) {
            // we probably have outdated info
            mnodeman.AskForMN(pfrom, dsq.vin);
            return;
        }

        // if the queue is ready, submit if we can
        if(dsq.fReady) {
            if(!infoMixingMasternode.fInfoValid) return;
            if(infoMixingMasternode.addr != infoMn.addr) {
                LogPrintf("PPQUEUE -- message doesn't match current Masternode: infoMixingMasternode=%s, addr=%s\n", infoMixingMasternode.addr.ToString(), infoMn.addr.ToString());
                return;
            }

            if(nState == POOL_STATE_QUEUE) {
                LogPrint("privatepay", "PPQUEUE -- PrivatePay queue (%s) is ready on masternode %s\n", dsq.ToString(), infoMn.addr.ToString());
                SubmitDenominate();
            }
        } else {
            BOOST_FOREACH(CPrivatepayQueue q, vecPrivatepayQueue) {
                if(q.vin == dsq.vin) {
                    // no way same mn can send another "not yet ready" dsq this soon
                    LogPrint("privatepay", "PPQUEUE -- Masternode %s is sending WAY too many dsq messages\n", infoMn.addr.ToString());
                    return;
                }
            }

            int nThreshold = infoMn.nLastDsq + mnodeman.CountEnabled(MIN_PRIVATEPAY_PEER_PROTO_VERSION)/5;
            LogPrint("privatepay", "PPQUEUE -- nLastDsq: %d  threshold: %d  nDsqCount: %d\n", infoMn.nLastDsq, nThreshold, mnodeman.nDsqCount);
            //don't allow a few nodes to dominate the queuing process
            if(infoMn.nLastDsq != 0 && nThreshold > mnodeman.nDsqCount) {
                LogPrint("privatepay", "PPQUEUE -- Masternode %s is sending too many dsq messages\n", infoMn.addr.ToString());
                return;
            }
            mnodeman.nDsqCount++;

            if(!mnodeman.UpdateLastDsq(dsq.vin)) return;

            LogPrint("privatepay", "PPQUEUE -- new PrivatePay queue (%s) from masternode %s\n", dsq.ToString(), infoMn.addr.ToString());
            if(infoMixingMasternode.fInfoValid && infoMixingMasternode.vin.prevout == dsq.vin.prevout) {
                dsq.fTried = true;
            }
            vecPrivatepayQueue.push_back(dsq);
            dsq.Relay();
        }

    } else if(strCommand == NetMsgType::PPSTATUSUPDATE) {

        if(pfrom->nVersion < MIN_PRIVATEPAY_PEER_PROTO_VERSION) {
            LogPrintf("PPSTATUSUPDATE -- incompatible version! nVersion: %d\n", pfrom->nVersion);
            return;
        }

        if(!infoMixingMasternode.fInfoValid) return;
        if(infoMixingMasternode.addr != pfrom->addr) {
            //LogPrintf("PPSTATUSUPDATE -- message doesn't match current Masternode: infoMixingMasternode %s addr %s\n", infoMixingMasternode.addr.ToString(), pfrom->addr.ToString());
            return;
        }

        int nMsgSessionID;
        int nMsgState;
        int nMsgEntriesCount;
        int nMsgStatusUpdate;
        int nMsgMessageID;
        vRecv >> nMsgSessionID >> nMsgState >> nMsgEntriesCount >> nMsgStatusUpdate >> nMsgMessageID;

        LogPrint("privatepay", "PPSTATUSUPDATE -- nMsgSessionID %d  nMsgState: %d  nEntriesCount: %d  nMsgStatusUpdate: %d  nMsgMessageID %d\n",
                nMsgSessionID, nMsgState, nEntriesCount, nMsgStatusUpdate, nMsgMessageID);

        if(nMsgState < POOL_STATE_MIN || nMsgState > POOL_STATE_MAX) {
            LogPrint("privatepay", "PPSTATUSUPDATE -- nMsgState is out of bounds: %d\n", nMsgState);
            return;
        }

        if(nMsgStatusUpdate < STATUS_REJECTED || nMsgStatusUpdate > STATUS_ACCEPTED) {
            LogPrint("privatepay", "PPSTATUSUPDATE -- nMsgStatusUpdate is out of bounds: %d\n", nMsgStatusUpdate);
            return;
        }

        if(nMsgMessageID < MSG_POOL_MIN || nMsgMessageID > MSG_POOL_MAX) {
            LogPrint("privatepay", "PPSTATUSUPDATE -- nMsgMessageID is out of bounds: %d\n", nMsgMessageID);
            return;
        }

        LogPrint("privatepay", "PPSTATUSUPDATE -- GetMessageByID: %s\n", CPrivatePay::GetMessageByID(PoolMessage(nMsgMessageID)));

        if(!CheckPoolStateUpdate(PoolState(nMsgState), nMsgEntriesCount, PoolStatusUpdate(nMsgStatusUpdate), PoolMessage(nMsgMessageID), nMsgSessionID)) {
            LogPrint("privatepay", "PPSTATUSUPDATE -- CheckPoolStateUpdate failed\n");
        }

    } else if(strCommand == NetMsgType::PPFINALTX) {

        if(pfrom->nVersion < MIN_PRIVATEPAY_PEER_PROTO_VERSION) {
            LogPrintf("PPFINALTX -- incompatible version! nVersion: %d\n", pfrom->nVersion);
            return;
        }

        if(!infoMixingMasternode.fInfoValid) return;
        if(infoMixingMasternode.addr != pfrom->addr) {
            //LogPrintf("PPFINALTX -- message doesn't match current Masternode: infoMixingMasternode %s addr %s\n", infoMixingMasternode.addr.ToString(), pfrom->addr.ToString());
            return;
        }

        int nMsgSessionID;
        CTransaction txNew;
        vRecv >> nMsgSessionID >> txNew;

        if(nSessionID != nMsgSessionID) {
            LogPrint("privatepay", "PPFINALTX -- message doesn't match current PrivatePay session: nSessionID: %d  nMsgSessionID: %d\n", nSessionID, nMsgSessionID);
            return;
        }

        LogPrint("privatepay", "PPFINALTX -- txNew %s", txNew.ToString());

        //check to see if input is spent already? (and probably not confirmed)
        SignFinalTransaction(txNew, pfrom);

    } else if(strCommand == NetMsgType::PPCOMPLETE) {

        if(pfrom->nVersion < MIN_PRIVATEPAY_PEER_PROTO_VERSION) {
            LogPrintf("PPCOMPLETE -- incompatible version! nVersion: %d\n", pfrom->nVersion);
            return;
        }

        if(!infoMixingMasternode.fInfoValid) return;
        if(infoMixingMasternode.addr != pfrom->addr) {
            LogPrint("privatepay", "PPCOMPLETE -- message doesn't match current Masternode: infoMixingMasternode=%s  addr=%s\n", infoMixingMasternode.addr.ToString(), pfrom->addr.ToString());
            return;
        }

        int nMsgSessionID;
        int nMsgMessageID;
        vRecv >> nMsgSessionID >> nMsgMessageID;

        if(nMsgMessageID < MSG_POOL_MIN || nMsgMessageID > MSG_POOL_MAX) {
            LogPrint("privatepay", "PPCOMPLETE -- nMsgMessageID is out of bounds: %d\n", nMsgMessageID);
            return;
        }

        if(nSessionID != nMsgSessionID) {
            LogPrint("privatepay", "PPCOMPLETE -- message doesn't match current PrivatePay session: nSessionID: %d  nMsgSessionID: %d\n", nSessionID, nMsgSessionID);
            return;
        }

        LogPrint("privatepay", "PPCOMPLETE -- nMsgSessionID %d  nMsgMessageID %d (%s)\n", nMsgSessionID, nMsgMessageID, CPrivatePay::GetMessageByID(PoolMessage(nMsgMessageID)));

        CompletedTransaction(PoolMessage(nMsgMessageID));
    }
}

void CPrivatePayClient::ResetPool()
{
    nCachedLastSuccessBlock = 0;
    txMyCollateral = CMutableTransaction();
    vecMasternodesUsed.clear();
    UnlockCoins();
    SetNull();
}

void CPrivatePayClient::SetNull()
{
    // Client side
    nEntriesCount = 0;
    fLastEntryAccepted = false;
    infoMixingMasternode = masternode_info_t();

    CPrivatePayBase::SetNull();
}

//
// Unlock coins after mixing fails or succeeds
//
void CPrivatePayClient::UnlockCoins()
{
    while(true) {
        TRY_LOCK(pwalletMain->cs_wallet, lockWallet);
        if(!lockWallet) {MilliSleep(50); continue;}
        BOOST_FOREACH(COutPoint outpoint, vecOutPointLocked)
            pwalletMain->UnlockCoin(outpoint);
        break;
    }

    vecOutPointLocked.clear();
}

std::string CPrivatePayClient::GetStatus()
{
    static int nStatusMessageProgress = 0;
    nStatusMessageProgress += 10;
    std::string strSuffix = "";

    if((pCurrentBlockIndex && pCurrentBlockIndex->nHeight - nCachedLastSuccessBlock < nMinBlockSpacing) || !masternodeSync.IsBlockchainSynced())
        return strAutoDenomResult;

    switch(nState) {
        case POOL_STATE_IDLE:
            return _("PrivatePay is idle.");
        case POOL_STATE_QUEUE:
            if(     nStatusMessageProgress % 70 <= 30) strSuffix = ".";
            else if(nStatusMessageProgress % 70 <= 50) strSuffix = "..";
            else if(nStatusMessageProgress % 70 <= 70) strSuffix = "...";
            return strprintf(_("Submitted to masternode, waiting in queue %s"), strSuffix);;
        case POOL_STATE_ACCEPTING_ENTRIES:
            if(nEntriesCount == 0) {
                nStatusMessageProgress = 0;
                return strAutoDenomResult;
            } else if(fLastEntryAccepted) {
                if(nStatusMessageProgress % 10 > 8) {
                    fLastEntryAccepted = false;
                    nStatusMessageProgress = 0;
                }
                return _("PrivatePay request complete:") + " " + _("Your transaction was accepted into the pool!");
            } else {
                if(     nStatusMessageProgress % 70 <= 40) return strprintf(_("Submitted following entries to masternode: %u / %d"), nEntriesCount, CPrivatePay::GetMaxPoolTransactions());
                else if(nStatusMessageProgress % 70 <= 50) strSuffix = ".";
                else if(nStatusMessageProgress % 70 <= 60) strSuffix = "..";
                else if(nStatusMessageProgress % 70 <= 70) strSuffix = "...";
                return strprintf(_("Submitted to masternode, waiting for more entries ( %u / %d ) %s"), nEntriesCount, CPrivatePay::GetMaxPoolTransactions(), strSuffix);
            }
        case POOL_STATE_SIGNING:
            if(     nStatusMessageProgress % 70 <= 40) return _("Found enough users, signing ...");
            else if(nStatusMessageProgress % 70 <= 50) strSuffix = ".";
            else if(nStatusMessageProgress % 70 <= 60) strSuffix = "..";
            else if(nStatusMessageProgress % 70 <= 70) strSuffix = "...";
            return strprintf(_("Found enough users, signing ( waiting %s )"), strSuffix);
        case POOL_STATE_ERROR:
            return _("PrivatePay request incomplete:") + " " + strLastMessage + " " + _("Will retry...");
        case POOL_STATE_SUCCESS:
            return _("PrivatePay request complete:") + " " + strLastMessage;
       default:
            return strprintf(_("Unknown state: id = %u"), nState);
    }
}

//
// Check the mixing progress and send client updates if a Masternode
//
void CPrivatePayClient::CheckPool()
{
    // reset if we're here for 10 seconds
    if((nState == POOL_STATE_ERROR || nState == POOL_STATE_SUCCESS) && GetTimeMillis() - nTimeLastSuccessfulStep >= 10000) {
        LogPrint("privatepay", "CPrivatePayClient::CheckPool -- timeout, RESETTING\n");
        UnlockCoins();
        SetNull();
    }
}

//
// Check for various timeouts (queue objects, mixing, etc)
//
void CPrivatePayClient::CheckTimeout()
{
    {
        TRY_LOCK(cs_privatepay, lockDS);
        if(!lockDS) return; // it's ok to fail here, we run this quite frequently

        // check mixing queue objects for timeouts
        std::vector<CPrivatepayQueue>::iterator it = vecPrivatepayQueue.begin();
        while(it != vecPrivatepayQueue.end()) {
            if((*it).IsExpired()) {
                LogPrint("privatepay", "CPrivatePayClient::CheckTimeout -- Removing expired queue (%s)\n", (*it).ToString());
                it = vecPrivatepayQueue.erase(it);
            } else ++it;
        }
    }

    if(!fEnablePrivatePay && !fMasterNode) return;

    // catching hanging sessions
    if(!fMasterNode) {
        switch(nState) {
            case POOL_STATE_ERROR:
                LogPrint("privatepay", "CPrivatePayClient::CheckTimeout -- Pool error -- Running CheckPool\n");
                CheckPool();
                break;
            case POOL_STATE_SUCCESS:
                LogPrint("privatepay", "CPrivatePayClient::CheckTimeout -- Pool success -- Running CheckPool\n");
                CheckPool();
                break;
            default:
                break;
        }
    }

    int nLagTime = fMasterNode ? 0 : 10000; // if we're the client, give the server a few extra seconds before resetting.
    int nTimeout = (nState == POOL_STATE_SIGNING) ? PRIVATEPAY_SIGNING_TIMEOUT : PRIVATEPAY_QUEUE_TIMEOUT;
    bool fTimeout = GetTimeMillis() - nTimeLastSuccessfulStep >= nTimeout*1000 + nLagTime;

    if(nState != POOL_STATE_IDLE && fTimeout) {
        LogPrint("privatepay", "CPrivatePayClient::CheckTimeout -- %s timed out (%ds) -- restting\n",
                (nState == POOL_STATE_SIGNING) ? "Signing" : "Session", nTimeout);
        UnlockCoins();
        SetNull();
        SetState(POOL_STATE_ERROR);
        strLastMessage = _("Session timed out.");
    }
}

//
// Execute a mixing denomination via a Masternode.
// This is only ran from clients
//
bool CPrivatePayClient::SendDenominate(const std::vector<CTxIn>& vecTxIn, const std::vector<CTxOut>& vecTxOut)
{
    if(fMasterNode) {
        LogPrintf("CPrivatePayClient::SendDenominate -- PrivatePay from a Masternode is not supported currently.\n");
        return false;
    }

    if(txMyCollateral == CMutableTransaction()) {
        LogPrintf("CPrivatePayClient:SendDenominate -- PrivatePay collateral not set\n");
        return false;
    }

    // lock the funds we're going to use
    BOOST_FOREACH(CTxIn txin, txMyCollateral.vin)
        vecOutPointLocked.push_back(txin.prevout);

    BOOST_FOREACH(CTxIn txin, vecTxIn)
        vecOutPointLocked.push_back(txin.prevout);

    // we should already be connected to a Masternode
    if(!nSessionID) {
        LogPrintf("CPrivatePayClient::SendDenominate -- No Masternode has been selected yet.\n");
        UnlockCoins();
        SetNull();
        return false;
    }

    if(!CheckDiskSpace()) {
        UnlockCoins();
        SetNull();
        fEnablePrivatePay = false;
        LogPrintf("CPrivatePayClient::SendDenominate -- Not enough disk space, disabling PrivatePay.\n");
        return false;
    }

    SetState(POOL_STATE_ACCEPTING_ENTRIES);
    strLastMessage = "";

    LogPrintf("CPrivatePayClient::SendDenominate -- Added transaction to pool.\n");

    //check it against the memory pool to make sure it's valid
    {
        CValidationState validationState;
        CMutableTransaction tx;

        BOOST_FOREACH(const CTxIn& txin, vecTxIn) {
            LogPrint("privatepay", "CPrivatePayClient::SendDenominate -- txin=%s\n", txin.ToString());
            tx.vin.push_back(txin);
        }

        BOOST_FOREACH(const CTxOut& txout, vecTxOut) {
            LogPrint("privatepay", "CPrivatePayClient::SendDenominate -- txout=%s\n", txout.ToString());
            tx.vout.push_back(txout);
        }

        LogPrintf("CPrivatePayClient::SendDenominate -- Submitting partial tx %s", tx.ToString());

        mempool.PrioritiseTransaction(tx.GetHash(), tx.GetHash().ToString(), 1000, 0.1*COIN);
        TRY_LOCK(cs_main, lockMain);
        if(!lockMain || !AcceptToMemoryPool(mempool, validationState, CTransaction(tx), false, NULL, false, true, true)) {
            LogPrintf("CPrivatePayClient::SendDenominate -- AcceptToMemoryPool() failed! tx=%s", tx.ToString());
            UnlockCoins();
            SetNull();
            return false;
        }
    }

    // store our entry for later use
    CPrivatePayEntry entry(vecTxIn, vecTxOut, txMyCollateral);
    vecEntries.push_back(entry);
    RelayIn(entry);
    nTimeLastSuccessfulStep = GetTimeMillis();

    return true;
}

// Incoming message from Masternode updating the progress of mixing
bool CPrivatePayClient::CheckPoolStateUpdate(PoolState nStateNew, int nEntriesCountNew, PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID, int nSessionIDNew)
{
    if(fMasterNode) return false;

    // do not update state when mixing client state is one of these
    if(nState == POOL_STATE_IDLE || nState == POOL_STATE_ERROR || nState == POOL_STATE_SUCCESS) return false;

    strAutoDenomResult = _("Masternode:") + " " + CPrivatePay::GetMessageByID(nMessageID);

    // if rejected at any state
    if(nStatusUpdate == STATUS_REJECTED) {
        LogPrintf("CPrivatePayClient::CheckPoolStateUpdate -- entry is rejected by Masternode\n");
        UnlockCoins();
        SetNull();
        SetState(POOL_STATE_ERROR);
        strLastMessage = CPrivatePay::GetMessageByID(nMessageID);
        return true;
    }

    if(nStatusUpdate == STATUS_ACCEPTED && nState == nStateNew) {
        if(nStateNew == POOL_STATE_QUEUE && nSessionID == 0 && nSessionIDNew != 0) {
            // new session id should be set only in POOL_STATE_QUEUE state
            nSessionID = nSessionIDNew;
            nTimeLastSuccessfulStep = GetTimeMillis();
            LogPrintf("CPrivatePayClient::CheckPoolStateUpdate -- set nSessionID to %d\n", nSessionID);
            return true;
        }
        else if(nStateNew == POOL_STATE_ACCEPTING_ENTRIES && nEntriesCount != nEntriesCountNew) {
            nEntriesCount = nEntriesCountNew;
            nTimeLastSuccessfulStep = GetTimeMillis();
            fLastEntryAccepted = true;
            LogPrintf("CPrivatePayClient::CheckPoolStateUpdate -- new entry accepted!\n");
            return true;
        }
    }

    // only situations above are allowed, fail in any other case
    return false;
}

//
// After we receive the finalized transaction from the Masternode, we must
// check it to make sure it's what we want, then sign it if we agree.
// If we refuse to sign, it's possible we'll be charged collateral
//
bool CPrivatePayClient::SignFinalTransaction(const CTransaction& finalTransactionNew, CNode* pnode)
{
    if(fMasterNode || pnode == NULL) return false;

    finalMutableTransaction = finalTransactionNew;
    LogPrintf("CPrivatePayClient::SignFinalTransaction -- finalMutableTransaction=%s", finalMutableTransaction.ToString());

    std::vector<CTxIn> sigs;

    //make sure my inputs/outputs are present, otherwise refuse to sign
    BOOST_FOREACH(const CPrivatePayEntry entry, vecEntries) {
        BOOST_FOREACH(const CTxDSIn txdsin, entry.vecTxDSIn) {
            /* Sign my transaction and all outputs */
            int nMyInputIndex = -1;
            CScript prevPubKey = CScript();
            CTxIn txin = CTxIn();

            for(unsigned int i = 0; i < finalMutableTransaction.vin.size(); i++) {
                if(finalMutableTransaction.vin[i] == txdsin) {
                    nMyInputIndex = i;
                    prevPubKey = txdsin.prevPubKey;
                    txin = txdsin;
                }
            }

            if(nMyInputIndex >= 0) { //might have to do this one input at a time?
                int nFoundOutputsCount = 0;
                CAmount nValue1 = 0;
                CAmount nValue2 = 0;

                for(unsigned int i = 0; i < finalMutableTransaction.vout.size(); i++) {
                    BOOST_FOREACH(const CTxOut& txout, entry.vecTxDSOut) {
                        if(finalMutableTransaction.vout[i] == txout) {
                            nFoundOutputsCount++;
                            nValue1 += finalMutableTransaction.vout[i].nValue;
                        }
                    }
                }

                BOOST_FOREACH(const CTxOut txout, entry.vecTxDSOut)
                    nValue2 += txout.nValue;

                int nTargetOuputsCount = entry.vecTxDSOut.size();
                if(nFoundOutputsCount < nTargetOuputsCount || nValue1 != nValue2) {
                    // in this case, something went wrong and we'll refuse to sign. It's possible we'll be charged collateral. But that's
                    // better then signing if the transaction doesn't look like what we wanted.
                    LogPrintf("CPrivatePayClient::SignFinalTransaction -- My entries are not correct! Refusing to sign: nFoundOutputsCount: %d, nTargetOuputsCount: %d\n", nFoundOutputsCount, nTargetOuputsCount);
                    UnlockCoins();
                    SetNull();

                    return false;
                }

                const CKeyStore& keystore = *pwalletMain;

                LogPrint("privatepay", "CPrivatePayClient::SignFinalTransaction -- Signing my input %i\n", nMyInputIndex);
                if(!SignSignature(keystore, prevPubKey, finalMutableTransaction, nMyInputIndex, int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))) { // changes scriptSig
                    LogPrint("privatepay", "CPrivatePayClient::SignFinalTransaction -- Unable to sign my own transaction!\n");
                    // not sure what to do here, it will timeout...?
                }

                sigs.push_back(finalMutableTransaction.vin[nMyInputIndex]);
                LogPrint("privatepay", "CPrivatePayClient::SignFinalTransaction -- nMyInputIndex: %d, sigs.size(): %d, scriptSig=%s\n", nMyInputIndex, (int)sigs.size(), ScriptToAsmStr(finalMutableTransaction.vin[nMyInputIndex].scriptSig));
            }
        }
    }

    if(sigs.empty()) {
        LogPrintf("CPrivatePayClient::SignFinalTransaction -- can't sign anything!\n");
        UnlockCoins();
        SetNull();

        return false;
    }

    // push all of our signatures to the Masternode
    LogPrintf("CPrivatePayClient::SignFinalTransaction -- pushing sigs to the masternode, finalMutableTransaction=%s", finalMutableTransaction.ToString());
    g_connman->PushMessage(pnode, NetMsgType::PPSIGNFINALTX, sigs);
    SetState(POOL_STATE_SIGNING);
    nTimeLastSuccessfulStep = GetTimeMillis();

    return true;
}

void CPrivatePayClient::NewBlock()
{
    static int64_t nTimeNewBlockReceived = 0;

    //we we're processing lots of blocks, we'll just leave
    if(GetTime() - nTimeNewBlockReceived < 10) return;
    nTimeNewBlockReceived = GetTime();
    LogPrint("privatepay", "CPrivatePayClient::NewBlock\n");

    CheckTimeout();
}

// mixing transaction was completed (failed or successful)
void CPrivatePayClient::CompletedTransaction(PoolMessage nMessageID)
{
    if(fMasterNode) return;

    if(nMessageID == MSG_SUCCESS) {
        LogPrintf("CompletedTransaction -- success\n");
        nCachedLastSuccessBlock = pCurrentBlockIndex->nHeight;
    } else {
        LogPrintf("CompletedTransaction -- error\n");
    }
    UnlockCoins();
    SetNull();
    strLastMessage = CPrivatePay::GetMessageByID(nMessageID);
}


bool CPrivatePayClient::CheckAutomaticBackup()
{
    switch(nWalletBackups) {
        case 0:
            LogPrint("privatepay", "CPrivatePayClient::CheckAutomaticBackup -- Automatic backups disabled, no mixing available.\n");
            strAutoDenomResult = _("Automatic backups disabled") + ", " + _("no mixing available.");
            fEnablePrivatePay = false; // stop mixing
            pwalletMain->nKeysLeftSinceAutoBackup = 0; // no backup, no "keys since last backup"
            return false;
        case -1:
            // Automatic backup failed, nothing else we can do until user fixes the issue manually.
            // There is no way to bring user attention in daemon mode so we just update status and
            // keep spaming if debug is on.
            LogPrint("privatepay", "CPrivatePayClient::CheckAutomaticBackup -- ERROR! Failed to create automatic backup.\n");
            strAutoDenomResult = _("ERROR! Failed to create automatic backup") + ", " + _("see debug.log for details.");
            return false;
        case -2:
            // We were able to create automatic backup but keypool was not replenished because wallet is locked.
            // There is no way to bring user attention in daemon mode so we just update status and
            // keep spaming if debug is on.
            LogPrint("privatepay", "CPrivatePayClient::CheckAutomaticBackup -- WARNING! Failed to create replenish keypool, please unlock your wallet to do so.\n");
            strAutoDenomResult = _("WARNING! Failed to replenish keypool, please unlock your wallet to do so.") + ", " + _("see debug.log for details.");
            return false;
    }

    if(pwalletMain->nKeysLeftSinceAutoBackup < PRIVATEPAY_KEYS_THRESHOLD_STOP) {
        // We should never get here via mixing itself but probably smth else is still actively using keypool
        LogPrint("privatepay", "CPrivatePayClient::CheckAutomaticBackup -- Very low number of keys left: %d, no mixing available.\n", pwalletMain->nKeysLeftSinceAutoBackup);
        strAutoDenomResult = strprintf(_("Very low number of keys left: %d") + ", " + _("no mixing available."), pwalletMain->nKeysLeftSinceAutoBackup);
        // It's getting really dangerous, stop mixing
        fEnablePrivatePay = false;
        return false;
    } else if(pwalletMain->nKeysLeftSinceAutoBackup < PRIVATEPAY_KEYS_THRESHOLD_WARNING) {
        // Low number of keys left but it's still more or less safe to continue
        LogPrint("privatepay", "CPrivatePayClient::CheckAutomaticBackup -- Very low number of keys left: %d\n", pwalletMain->nKeysLeftSinceAutoBackup);
        strAutoDenomResult = strprintf(_("Very low number of keys left: %d"), pwalletMain->nKeysLeftSinceAutoBackup);

        if(fCreateAutoBackups) {
            LogPrint("privatepay", "CPrivatePayClient::CheckAutomaticBackup -- Trying to create new backup.\n");
            std::string warningString;
            std::string errorString;

            if(!AutoBackupWallet(pwalletMain, "", warningString, errorString)) {
                if(!warningString.empty()) {
                    // There were some issues saving backup but yet more or less safe to continue
                    LogPrintf("CPrivatePayClient::CheckAutomaticBackup -- WARNING! Something went wrong on automatic backup: %s\n", warningString);
                }
                if(!errorString.empty()) {
                    // Things are really broken
                    LogPrintf("CPrivatePayClient::CheckAutomaticBackup -- ERROR! Failed to create automatic backup: %s\n", errorString);
                    strAutoDenomResult = strprintf(_("ERROR! Failed to create automatic backup") + ": %s", errorString);
                    return false;
                }
            }
        } else {
            // Wait for smth else (e.g. GUI action) to create automatic backup for us
            return false;
        }
    }

    LogPrint("privatepay", "CPrivatePayClient::CheckAutomaticBackup -- Keys left since latest backup: %d\n", pwalletMain->nKeysLeftSinceAutoBackup);

    return true;
}

//
// Passively run mixing in the background to anonymize funds based on the given configuration.
//
bool CPrivatePayClient::DoAutomaticDenominating(CConnman& connman, bool fDryRun)
{
    if(!fEnablePrivatePay || fMasterNode || !pCurrentBlockIndex) return false;
    if(!pwalletMain || pwalletMain->IsLocked(true)) return false;
    if(nState != POOL_STATE_IDLE) return false;

    if(!masternodeSync.IsMasternodeListSynced()) {
        strAutoDenomResult = _("Can't mix while sync in progress.");
        return false;
    }

    if(!CheckAutomaticBackup())
        return false;

    if(GetEntriesCount() > 0) {
        strAutoDenomResult = _("Mixing in progress...");
        return false;
    }

    TRY_LOCK(cs_privatepay, lockDS);
    if(!lockDS) {
        strAutoDenomResult = _("Lock is already in place.");
        return false;
    }

    if(!fDryRun && pwalletMain->IsLocked(true)) {
        strAutoDenomResult = _("Wallet is locked.");
        return false;
    }

    if(!fPrivatePayMultiSession && pCurrentBlockIndex->nHeight - nCachedLastSuccessBlock < nMinBlockSpacing) {
        LogPrintf("CPrivatePayClient::DoAutomaticDenominating -- Last successful PrivatePay action was too recent\n");
        strAutoDenomResult = _("Last successful PrivatePay action was too recent.");
        return false;
    }

    if(mnodeman.size() == 0) {
        LogPrint("privatepay", "CPrivatePayClient::DoAutomaticDenominating -- No Masternodes detected\n");
        strAutoDenomResult = _("No Masternodes detected.");
        return false;
    }

    CAmount nValueMin = CPrivatePay::GetSmallestDenomination();

    // if there are no confirmed DS collateral inputs yet
    if(!pwalletMain->HasCollateralInputs()) {
        // should have some additional amount for them
        nValueMin += CPrivatePay::GetMaxCollateralAmount();
    }

    // including denoms but applying some restrictions
    CAmount nBalanceNeedsAnonymized = pwalletMain->GetNeedsToBeAnonymizedBalance(nValueMin);

    // anonymizable balance is way too small
    if(nBalanceNeedsAnonymized < nValueMin) {
        LogPrintf("CPrivatePayClient::DoAutomaticDenominating -- Not enough funds to anonymize\n");
        strAutoDenomResult = _("Not enough funds to anonymize.");
        return false;
    }

    // excluding denoms
    CAmount nBalanceAnonimizableNonDenom = pwalletMain->GetAnonymizableBalance(true);
    // denoms
    CAmount nBalanceDenominatedConf = pwalletMain->GetDenominatedBalance();
    CAmount nBalanceDenominatedUnconf = pwalletMain->GetDenominatedBalance(true);
    CAmount nBalanceDenominated = nBalanceDenominatedConf + nBalanceDenominatedUnconf;

    LogPrint("privatepay", "CPrivatePayClient::DoAutomaticDenominating -- nValueMin: %f, nBalanceNeedsAnonymized: %f, nBalanceAnonimizableNonDenom: %f, nBalanceDenominatedConf: %f, nBalanceDenominatedUnconf: %f, nBalanceDenominated: %f\n",
            (float)nValueMin/COIN,
            (float)nBalanceNeedsAnonymized/COIN,
            (float)nBalanceAnonimizableNonDenom/COIN,
            (float)nBalanceDenominatedConf/COIN,
            (float)nBalanceDenominatedUnconf/COIN,
            (float)nBalanceDenominated/COIN);

    if(fDryRun) return true;

    // Check if we have should create more denominated inputs i.e.
    // there are funds to denominate and denominated balance does not exceed
    // max amount to mix yet.
    if(nBalanceAnonimizableNonDenom >= nValueMin + CPrivatePay::GetCollateralAmount() && nBalanceDenominated < nPrivatePayAmount*COIN)
        return CreateDenominated(connman);

    //check if we have the collateral sized inputs
    if(!pwalletMain->HasCollateralInputs())
        return !pwalletMain->HasCollateralInputs(false) && MakeCollateralAmounts(connman);

    if(nSessionID) {
        strAutoDenomResult = _("Mixing in progress...");
        return false;
    }

    // Initial phase, find a Masternode
    // Clean if there is anything left from previous session
    UnlockCoins();
    SetNull();

    // should be no unconfirmed denoms in non-multi-session mode
    if(!fPrivatePayMultiSession && nBalanceDenominatedUnconf > 0) {
        LogPrintf("CPrivatePayClient::DoAutomaticDenominating -- Found unconfirmed denominated outputs, will wait till they confirm to continue.\n");
        strAutoDenomResult = _("Found unconfirmed denominated outputs, will wait till they confirm to continue.");
        return false;
    }

    //check our collateral and create new if needed
    std::string strReason;
    if(txMyCollateral == CMutableTransaction()) {
        if(!pwalletMain->CreateCollateralTransaction(txMyCollateral, strReason)) {
            LogPrintf("CPrivatePayClient::DoAutomaticDenominating -- create collateral error:%s\n", strReason);
            return false;
        }
    } else {
        if(!CPrivatePay::IsCollateralValid(txMyCollateral)) {
            LogPrintf("CPrivatePayClient::DoAutomaticDenominating -- invalid collateral, recreating...\n");
            if(!pwalletMain->CreateCollateralTransaction(txMyCollateral, strReason)) {
                LogPrintf("CPrivatePayClient::DoAutomaticDenominating -- create collateral error: %s\n", strReason);
                return false;
            }
        }
    }

    int nMnCountEnabled = mnodeman.CountEnabled(MIN_PRIVATEPAY_PEER_PROTO_VERSION);

    // If we've used 90% of the Masternode list then drop the oldest first ~30%
    int nThreshold_high = nMnCountEnabled * 0.9;
    int nThreshold_low = nThreshold_high * 0.7;
    LogPrint("privatepay", "Checking vecMasternodesUsed: size: %d, threshold: %d\n", (int)vecMasternodesUsed.size(), nThreshold_high);

    if((int)vecMasternodesUsed.size() > nThreshold_high) {
        vecMasternodesUsed.erase(vecMasternodesUsed.begin(), vecMasternodesUsed.begin() + vecMasternodesUsed.size() - nThreshold_low);
        LogPrint("privatepay", "  vecMasternodesUsed: new size: %d, threshold: %d\n", (int)vecMasternodesUsed.size(), nThreshold_high);
    }

    bool fUseQueue = GetRandInt(100) > 33;
    // don't use the queues all of the time for mixing unless we are a liquidity provider
    if((nLiquidityProvider || fUseQueue) && JoinExistingQueue(nBalanceNeedsAnonymized))
        return true;

    // do not initiate queue if we are a liquidity provider to avoid useless inter-mixing
    if(nLiquidityProvider) return false;

    if(StartNewQueue(nValueMin, nBalanceNeedsAnonymized))
        return true;

    strAutoDenomResult = _("No compatible Masternode found.");
    return false;
}

bool CPrivatePayClient::JoinExistingQueue(CAmount nBalanceNeedsAnonymized)
{
    std::vector<CAmount> vecStandardDenoms = CPrivatePay::GetStandardDenominations();
    // Look through the queues and see if anything matches
    BOOST_FOREACH(CPrivatepayQueue& dsq, vecPrivatepayQueue) {
        // only try each queue once
        if(dsq.fTried) continue;
        dsq.fTried = true;

        if(dsq.IsExpired()) continue;

        masternode_info_t infoMn = mnodeman.GetMasternodeInfo(dsq.vin);

        if(!infoMn.fInfoValid) {
            LogPrintf("CPrivatePayClient::JoinExistingQueue -- dsq masternode is not in masternode list, masternode=%s\n", dsq.vin.prevout.ToStringShort());
            continue;
        }

        if(infoMn.nProtocolVersion < MIN_PRIVATEPAY_PEER_PROTO_VERSION) continue;

        std::vector<int> vecBits;
        if(!CPrivatePay::GetDenominationsBits(dsq.nDenom, vecBits)) {
            // incompatible denom
            continue;
        }

        // mixing rate limit i.e. nLastDsq check should already pass in PPQUEUE ProcessMessage
        // in order for dsq to get into vecPrivatepayQueue, so we should be safe to mix already,
        // no need for additional verification here

        LogPrint("privatepay", "CPrivatePayClient::JoinExistingQueue -- found valid queue: %s\n", dsq.ToString());

        CAmount nValueInTmp = 0;
        std::vector<CTxIn> vecTxInTmp;
        std::vector<COutput> vCoinsTmp;

        // Try to match their denominations if possible, select at least 1 denominations
        if(!pwalletMain->SelectCoinsByDenominations(dsq.nDenom, vecStandardDenoms[vecBits.front()], nBalanceNeedsAnonymized, vecTxInTmp, vCoinsTmp, nValueInTmp, 0, nPrivatePayRounds)) {
            LogPrintf("CPrivatePayClient::JoinExistingQueue -- Couldn't match denominations %d %d (%s)\n", vecBits.front(), dsq.nDenom, CPrivatePay::GetDenominationsToString(dsq.nDenom));
            continue;
        }

        vecMasternodesUsed.push_back(dsq.vin);

        CNode* pnodeFound = NULL;
        bool fDisconnect = false;
        g_connman->ForNode(infoMn.addr, CConnman::AllNodes, [&pnodeFound, &fDisconnect](CNode* pnode) {
            pnodeFound = pnode;
            if(pnodeFound->fDisconnect) {
                fDisconnect = true;
            } else {
                pnodeFound->AddRef();
            }
            return true;
        });
        if (fDisconnect)
            continue;

        LogPrintf("CPrivatePayClient::JoinExistingQueue -- attempt to connect to masternode from queue, addr=%s\n", infoMn.addr.ToString());
        // connect to Masternode and submit the queue request
        // TODO: Pass CConnman instance somehow and don't use global variable.
        CNode* pnode = (pnodeFound && pnodeFound->fMasternode) ? pnodeFound : g_connman->ConnectNode(CAddress(infoMn.addr, NODE_NETWORK), NULL, true);
        if(pnode) {
            infoMixingMasternode = infoMn;
            nSessionDenom = dsq.nDenom;

            g_connman->PushMessage(pnode, NetMsgType::PPACCEPT, nSessionDenom, txMyCollateral);
            LogPrintf("CPrivatePayClient::JoinExistingQueue -- connected (from queue), sending PPACCEPT: nSessionDenom: %d (%s), addr=%s\n",
                    nSessionDenom, CPrivatePay::GetDenominationsToString(nSessionDenom), pnode->addr.ToString());
            strAutoDenomResult = _("Mixing in progress...");
            SetState(POOL_STATE_QUEUE);
            nTimeLastSuccessfulStep = GetTimeMillis();
            if(pnodeFound) {
                pnodeFound->Release();
            }
            return true;
        } else {
            LogPrintf("CPrivatePayClient::JoinExistingQueue -- can't connect, addr=%s\n", infoMn.addr.ToString());
            strAutoDenomResult = _("Error connecting to Masternode.");
            continue;
        }
    }
    return false;
}

bool CPrivatePayClient::StartNewQueue(CAmount nValueMin, CAmount nBalanceNeedsAnonymized)
{
    int nTries = 0;
    int nMnCountEnabled = mnodeman.CountEnabled(MIN_PRIVATEPAY_PEER_PROTO_VERSION);

    // ** find the coins we'll use
    std::vector<CTxIn> vecTxIn;
    CAmount nValueInTmp = 0;
    if(!pwalletMain->SelectCoinsDark(nValueMin, nBalanceNeedsAnonymized, vecTxIn, nValueInTmp, 0, nPrivatePayRounds)) {
        // this should never happen
        LogPrintf("CPrivatePayClient::StartNewQueue -- Can't mix: no compatible inputs found!\n");
        strAutoDenomResult = _("Can't mix: no compatible inputs found!");
        return false;
    }

    // otherwise, try one randomly
    while(nTries < 10) {
        masternode_info_t infoMn = mnodeman.FindRandomNotInVec(vecMasternodesUsed, MIN_PRIVATEPAY_PEER_PROTO_VERSION);
        if(!infoMn.fInfoValid) {
            LogPrintf("CPrivatePayClient::StartNewQueue -- Can't find random masternode!\n");
            strAutoDenomResult = _("Can't find random Masternode.");
            return false;
        }
        vecMasternodesUsed.push_back(infoMn.vin);

        if(infoMn.nLastDsq != 0 && infoMn.nLastDsq + nMnCountEnabled/5 > mnodeman.nDsqCount) {
            LogPrintf("CPrivatePayClient::StartNewQueue -- Too early to mix on this masternode!"
                        " masternode=%s  addr=%s  nLastDsq=%d  CountEnabled/5=%d  nDsqCount=%d\n",
                        infoMn.vin.prevout.ToStringShort(), infoMn.addr.ToString(), infoMn.nLastDsq,
                        nMnCountEnabled/5, mnodeman.nDsqCount);
            nTries++;
            continue;
        }

        CNode* pnodeFound = NULL;
        bool fDisconnect = false;
        g_connman->ForNode(infoMn.addr, CConnman::AllNodes, [&pnodeFound, &fDisconnect](CNode* pnode) {
            pnodeFound = pnode;
            if(pnodeFound->fDisconnect) {
                fDisconnect = true;
            } else {
                pnodeFound->AddRef();
            }
            return true;
        });
        if (fDisconnect) {
            nTries++;
            continue;
        }

        LogPrintf("CPrivatePayClient::StartNewQueue -- attempt %d connection to Masternode %s\n", nTries, infoMn.addr.ToString());
        // TODO: Pass CConnman instance somehow and don't use global variable.
        CNode* pnode = (pnodeFound && pnodeFound->fMasternode) ? pnodeFound : g_connman->ConnectNode(CAddress(infoMn.addr, NODE_NETWORK), NULL, true);
        if(pnode) {
            LogPrintf("CPrivatePayClient::StartNewQueue -- connected, addr=%s\n", infoMn.addr.ToString());
            infoMixingMasternode = infoMn;

            std::vector<CAmount> vecAmounts;
            pwalletMain->ConvertList(vecTxIn, vecAmounts);
            // try to get a single random denom out of vecAmounts
            while(nSessionDenom == 0) {
                nSessionDenom = CPrivatePay::GetDenominationsByAmounts(vecAmounts);
            }

            g_connman->PushMessage(pnode, NetMsgType::PPACCEPT, nSessionDenom, txMyCollateral);
            LogPrintf("CPrivatePayClient::StartNewQueue -- connected, sending PPACCEPT, nSessionDenom: %d (%s)\n",
                    nSessionDenom, CPrivatePay::GetDenominationsToString(nSessionDenom));
            strAutoDenomResult = _("Mixing in progress...");
            SetState(POOL_STATE_QUEUE);
            nTimeLastSuccessfulStep = GetTimeMillis();
            if(pnodeFound) {
                pnodeFound->Release();
            }
            return true;
        } else {
            LogPrintf("CPrivatePayClient::StartNewQueue -- can't connect, addr=%s\n", infoMn.addr.ToString());
            nTries++;
            continue;
        }
    }
    return false;
}

bool CPrivatePayClient::SubmitDenominate()
{
    std::string strError;
    std::vector<CTxIn> vecTxInRet;
    std::vector<CTxOut> vecTxOutRet;

    // Submit transaction to the pool if we get here
    // Try to use only inputs with the same number of rounds starting from the highest number of rounds possible
    for(int i = nPrivatePayRounds; i > 0; i--) {
        if(PrepareDenominate(i - 1, i, strError, vecTxInRet, vecTxOutRet)) {
            LogPrintf("CPrivatePayClient::SubmitDenominate -- Running PrivatePay denominate for %d rounds, success\n", i);
            return SendDenominate(vecTxInRet, vecTxOutRet);
        }
        LogPrint("privatepay", "CPrivatePayClient::SubmitDenominate -- Running PrivatePay denominate for %d rounds, error: %s\n", i, strError);
    }

    // We failed? That's strange but let's just make final attempt and try to mix everything
    if(PrepareDenominate(0, nPrivatePayRounds, strError, vecTxInRet, vecTxOutRet)) {
        LogPrintf("CPrivatePayClient::SubmitDenominate -- Running PrivatePay denominate for all rounds, success\n");
        return SendDenominate(vecTxInRet, vecTxOutRet);
    }

    // Should never actually get here but just in case
    LogPrintf("CPrivatePayClient::SubmitDenominate -- Running PrivatePay denominate for all rounds, error: %s\n", strError);
    strAutoDenomResult = strError;
    return false;
}

bool CPrivatePayClient::PrepareDenominate(int nMinRounds, int nMaxRounds, std::string& strErrorRet, std::vector<CTxIn>& vecTxInRet, std::vector<CTxOut>& vecTxOutRet)
{
    if(!pwalletMain) {
        strErrorRet = "Wallet is not initialized";
        return false;
    }

    if (pwalletMain->IsLocked(true)) {
        strErrorRet = "Wallet locked, unable to create transaction!";
        return false;
    }

    if (GetEntriesCount() > 0) {
        strErrorRet = "Already have pending entries in the PrivatePay pool";
        return false;
    }

    // make sure returning vectors are empty before filling them up
    vecTxInRet.clear();
    vecTxOutRet.clear();

    // ** find the coins we'll use
    std::vector<CTxIn> vecTxIn;
    std::vector<COutput> vCoins;
    CAmount nValueIn = 0;
    CReserveKey reservekey(pwalletMain);

    /*
        Select the coins we'll use

        if nMinRounds >= 0 it means only denominated inputs are going in and coming out
    */
    std::vector<int> vecBits;
    if (!CPrivatePay::GetDenominationsBits(nSessionDenom, vecBits)) {
        strErrorRet = "Incorrect session denom";
        return false;
    }
    std::vector<CAmount> vecStandardDenoms = CPrivatePay::GetStandardDenominations();
    bool fSelected = pwalletMain->SelectCoinsByDenominations(nSessionDenom, vecStandardDenoms[vecBits.front()], CPrivatePay::GetMaxPoolAmount(), vecTxIn, vCoins, nValueIn, nMinRounds, nMaxRounds);
    if (nMinRounds >= 0 && !fSelected) {
        strErrorRet = "Can't select current denominated inputs";
        return false;
    }

    LogPrintf("CPrivatePayClient::PrepareDenominate -- max value: %f\n", (double)nValueIn/COIN);

    {
        LOCK(pwalletMain->cs_wallet);
        BOOST_FOREACH(CTxIn txin, vecTxIn) {
            pwalletMain->LockCoin(txin.prevout);
        }
    }

    CAmount nValueLeft = nValueIn;

    // Try to add every needed denomination, repeat up to 5-PRIVATEPAY_ENTRY_MAX_SIZE times.
    // NOTE: No need to randomize order of inputs because they were
    // initially shuffled in CWallet::SelectCoinsByDenominations already.
    int nStep = 0;
    int nStepsMax = 5 + GetRandInt(PRIVATEPAY_ENTRY_MAX_SIZE-5+1);

    while (nStep < nStepsMax) {
        BOOST_FOREACH(int nBit, vecBits) {
            CAmount nValueDenom = vecStandardDenoms[nBit];
            if (nValueLeft - nValueDenom < 0) continue;

            // Note: this relies on a fact that both vectors MUST have same size
            std::vector<CTxIn>::iterator it = vecTxIn.begin();
            std::vector<COutput>::iterator it2 = vCoins.begin();
            while (it2 != vCoins.end()) {
                // we have matching inputs
                if ((*it2).tx->vout[(*it2).i].nValue == nValueDenom) {
                    // add new input in resulting vector
                    vecTxInRet.push_back(*it);
                    // remove corresponting items from initial vectors
                    vecTxIn.erase(it);
                    vCoins.erase(it2);

                    CScript scriptDenom;
                    CPubKey vchPubKey;
                    // use unique address
                    assert(reservekey.GetReservedKey(vchPubKey, false)); // should never fail, as we just unlocked
                    scriptDenom = GetScriptForDestination(vchPubKey.GetID());
                    reservekey.KeepKey();

                    // add new output
                    CTxOut txout(nValueDenom, scriptDenom);
                    vecTxOutRet.push_back(txout);

                    // subtract denomination amount
                    nValueLeft -= nValueDenom;

                    // step is complete
                    break;
                }
                ++it;
                ++it2;
            }
        }
        if(nValueLeft == 0) break;
        nStep++;
    }

    {
        // unlock unused coins
        LOCK(pwalletMain->cs_wallet);
        BOOST_FOREACH(CTxIn txin, vecTxIn) {
            pwalletMain->UnlockCoin(txin.prevout);
        }
    }

    if (CPrivatePay::GetDenominations(vecTxOutRet) != nSessionDenom) {
        // unlock used coins on failure
        LOCK(pwalletMain->cs_wallet);
        BOOST_FOREACH(CTxIn txin, vecTxInRet) {
            pwalletMain->UnlockCoin(txin.prevout);
        }
        strErrorRet = "Can't make current denominated outputs";
        return false;
    }

    // We also do not care about full amount as long as we have right denominations
    return true;
}

// Create collaterals by looping through inputs grouped by addresses
bool CPrivatePayClient::MakeCollateralAmounts(CConnman& connman)
{
    std::vector<CompactTallyItem> vecTally;
    if(!pwalletMain->SelectCoinsGrouppedByAddresses(vecTally, false)) {
        LogPrint("privatepay", "CPrivatePayClient::MakeCollateralAmounts -- SelectCoinsGrouppedByAddresses can't find any inputs!\n");
        return false;
    }

    // First try to use only non-denominated funds
    BOOST_FOREACH(CompactTallyItem& item, vecTally) {
        if(!MakeCollateralAmounts(item, false, connman)) continue;
        return true;
    }

    // There should be at least some denominated funds we should be able to break in pieces to continue mixing
    BOOST_FOREACH(CompactTallyItem& item, vecTally) {
        if(!MakeCollateralAmounts(item, true, connman)) continue;
        return true;
    }

    // If we got here then smth is terribly broken actually
    LogPrintf("CPrivatePayClient::MakeCollateralAmounts -- ERROR: Can't make collaterals!\n");
    return false;
}

// Split up large inputs or create fee sized inputs
bool CPrivatePayClient::MakeCollateralAmounts(const CompactTallyItem& tallyItem, bool fTryDenominated, CConnman& connman)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CWalletTx wtx;
    CAmount nFeeRet = 0;
    int nChangePosRet = -1;
    std::string strFail = "";
    std::vector<CRecipient> vecSend;

    // make our collateral address
    CReserveKey reservekeyCollateral(pwalletMain);
    // make our change address
    CReserveKey reservekeyChange(pwalletMain);

    CScript scriptCollateral;
    CPubKey vchPubKey;
    assert(reservekeyCollateral.GetReservedKey(vchPubKey, false)); // should never fail, as we just unlocked
    scriptCollateral = GetScriptForDestination(vchPubKey.GetID());

    vecSend.push_back((CRecipient){scriptCollateral, CPrivatePay::GetMaxCollateralAmount(), false});

    // try to use non-denominated and not mn-like funds first, select them explicitly
    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = false;
    coinControl.fAllowWatchOnly = false;
    // send change to the same address so that we were able create more denoms out of it later
    coinControl.destChange = tallyItem.address.Get();
    BOOST_FOREACH(const CTxIn& txin, tallyItem.vecTxIn)
        coinControl.Select(txin.prevout);

    bool fSuccess = pwalletMain->CreateTransaction(vecSend, wtx, reservekeyChange,
            nFeeRet, nChangePosRet, strFail, &coinControl, true, ONLY_NONDENOMINATED_NOT100000IFMN);
    if(!fSuccess) {
        LogPrintf("CPrivatePayClient::MakeCollateralAmounts -- ONLY_NONDENOMINATED_NOT100000IFMN Error: %s\n", strFail);
        // If we failed then most likeky there are not enough funds on this address.
        if(fTryDenominated) {
            // Try to also use denominated coins (we can't mix denominated without collaterals anyway).
            // MN-like funds should not be touched in any case.
            if(!pwalletMain->CreateTransaction(vecSend, wtx, reservekeyChange,
                                nFeeRet, nChangePosRet, strFail, &coinControl, true, ONLY_NOT100000IFMN)) {
                LogPrintf("CPrivatePayClient::MakeCollateralAmounts -- ONLY_NOT100000IFMN Error: %s\n", strFail);
                reservekeyCollateral.ReturnKey();
                return false;
            }
        } else {
            // Nothing else we can do.
            reservekeyCollateral.ReturnKey();
            return false;
        }
    }

    reservekeyCollateral.KeepKey();

    LogPrintf("CPrivatePayClient::MakeCollateralAmounts -- txid=%s\n", wtx.GetHash().GetHex());

    // use the same nCachedLastSuccessBlock as for DS mixinx to prevent race
    if(!pwalletMain->CommitTransaction(wtx, reservekeyChange, &connman)) {
        LogPrintf("CPrivatePayClient::MakeCollateralAmounts -- CommitTransaction failed!\n");
        return false;
    }

    nCachedLastSuccessBlock = pCurrentBlockIndex->nHeight;

    return true;
}

// Create denominations by looping through inputs grouped by addresses
bool CPrivatePayClient::CreateDenominated(CConnman& connman)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::vector<CompactTallyItem> vecTally;
    if(!pwalletMain->SelectCoinsGrouppedByAddresses(vecTally)) {
        LogPrint("privatepay", "CPrivatePayClient::CreateDenominated -- SelectCoinsGrouppedByAddresses can't find any inputs!\n");
        return false;
    }

    bool fCreateMixingCollaterals = !pwalletMain->HasCollateralInputs();

    BOOST_FOREACH(CompactTallyItem& item, vecTally) {
        if(!CreateDenominated(item, fCreateMixingCollaterals, connman)) continue;
        return true;
    }

    LogPrintf("CPrivatePayClient::CreateDenominated -- failed!\n");
    return false;
}

// Create denominations
bool CPrivatePayClient::CreateDenominated(const CompactTallyItem& tallyItem, bool fCreateMixingCollaterals, CConnman& connman)
{
    std::vector<CRecipient> vecSend;
    CAmount nValueLeft = tallyItem.nAmount;
    nValueLeft -= CPrivatePay::GetCollateralAmount(); // leave some room for fees

    LogPrintf("CreateDenominated0 nValueLeft: %f\n", (float)nValueLeft/COIN);
    // make our collateral address
    CReserveKey reservekeyCollateral(pwalletMain);

    CScript scriptCollateral;
    CPubKey vchPubKey;
    assert(reservekeyCollateral.GetReservedKey(vchPubKey, false)); // should never fail, as we just unlocked
    scriptCollateral = GetScriptForDestination(vchPubKey.GetID());

    // ****** Add collateral outputs ************ /

    if(fCreateMixingCollaterals) {
        vecSend.push_back((CRecipient){scriptCollateral, CPrivatePay::GetMaxCollateralAmount(), false});
        nValueLeft -= CPrivatePay::GetMaxCollateralAmount();
    }

    // ****** Add denoms ************ /

    // make our denom addresses
    std::vector<std::shared_ptr<CReserveKey>> reservekeyDenomVec;

    // try few times - skipping smallest denoms first if there are too much already, if failed - use them
    int nOutputsTotal = 0;
    bool fSkip = true;
    do {
        std::vector<CAmount> vecStandardDenoms = CPrivatePay::GetStandardDenominations();

        BOOST_REVERSE_FOREACH(CAmount nDenomValue, vecStandardDenoms) {

            if(fSkip) {
                // Note: denoms are skipped if there are already DENOMS_COUNT_MAX of them
                // and there are still larger denoms which can be used for mixing

                // check skipped denoms
                if(IsDenomSkipped(nDenomValue)) continue;

                // find new denoms to skip if any (ignore the largest one)
                if(nDenomValue != vecStandardDenoms.front() && pwalletMain->CountInputsWithAmount(nDenomValue) > DENOMS_COUNT_MAX) {
                    strAutoDenomResult = strprintf(_("Too many %f denominations, removing."), (float)nDenomValue/COIN);
                    LogPrintf("CPrivatePayClient::CreateDenominated -- %s\n", strAutoDenomResult);
                    vecDenominationsSkipped.push_back(nDenomValue);
                    continue;
                }
            }

            int nOutputs = 0;

            // add each output up to 11 times until it can't be added again
            while(nValueLeft - nDenomValue >= 0 && nOutputs <= 10) {
                CScript scriptDenom;
                CPubKey vchPubKey;
                // use a unique address
                std::shared_ptr<CReserveKey> reservekeyDenom = std::make_shared<CReserveKey>(pwalletMain);
                reservekeyDenomVec.push_back(reservekeyDenom);

                assert(reservekeyDenom->GetReservedKey(vchPubKey, false)); // should never fail, as we just unlocked
                scriptDenom = GetScriptForDestination(vchPubKey.GetID());

                vecSend.push_back((CRecipient){ scriptDenom, nDenomValue, false });

                //increment outputs and subtract denomination amount
                nOutputs++;
                nValueLeft -= nDenomValue;
                LogPrintf("CreateDenominated1: totalOutputs: %d, nOutputsTotal: %d, nOutputs: %d, nValueLeft: %f\n", nOutputsTotal + nOutputs, nOutputsTotal, nOutputs, (float)nValueLeft/COIN);
            }

            nOutputsTotal += nOutputs;
            if(nValueLeft == 0) break;
        }
        LogPrintf("CreateDenominated2: nOutputsTotal: %d, nValueLeft: %f\n", nOutputsTotal, (float)nValueLeft/COIN);
        // if there were no outputs added, start over without skipping
        fSkip = !fSkip;
    } while (nOutputsTotal == 0 && !fSkip);
    LogPrintf("CreateDenominated3: nOutputsTotal: %d, nValueLeft: %f\n", nOutputsTotal, (float)nValueLeft/COIN);

    // if we have anything left over, it will be automatically send back as change - there is no need to send it manually

    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = false;
    coinControl.fAllowWatchOnly = false;
    // send change to the same address so that we were able create more denoms out of it later
    coinControl.destChange = tallyItem.address.Get();
    BOOST_FOREACH(const CTxIn& txin, tallyItem.vecTxIn)
        coinControl.Select(txin.prevout);

    CWalletTx wtx;
    CAmount nFeeRet = 0;
    int nChangePosRet = -1;
    std::string strFail = "";
    // make our change address
    CReserveKey reservekeyChange(pwalletMain);

    bool fSuccess = pwalletMain->CreateTransaction(vecSend, wtx, reservekeyChange,
            nFeeRet, nChangePosRet, strFail, &coinControl, true, ONLY_NONDENOMINATED_NOT100000IFMN);
    if(!fSuccess) {
        LogPrintf("CPrivatePayClient::CreateDenominated -- Error: %s\n", strFail);
        for(auto key : reservekeyDenomVec)
            key->ReturnKey();
        reservekeyCollateral.ReturnKey();
        LogPrintf("CPrivatePayClient::CreateDenominated -- %d keys returned\n", reservekeyDenomVec.size() + 1);
        return false;
    }

    for(auto key : reservekeyDenomVec)
        key->KeepKey();
    reservekeyCollateral.KeepKey();
    LogPrintf("CPrivatePayClient::CreateDenominated -- %d keys keeped\n", reservekeyDenomVec.size() + 1);

    if(!pwalletMain->CommitTransaction(wtx, reservekeyChange, &connman)) {
        LogPrintf("CPrivatePayClient::CreateDenominated -- CommitTransaction failed!\n");
        return false;
    }

    // use the same nCachedLastSuccessBlock as for DS mixing to prevent race
    nCachedLastSuccessBlock = pCurrentBlockIndex->nHeight;
    LogPrintf("CPrivatePayClient::CreateDenominated -- txid=%s\n", wtx.GetHash().GetHex());

    return true;
}

void CPrivatePayClient::RelayIn(const CPrivatePayEntry& entry)
{
    if(!infoMixingMasternode.fInfoValid) return;

    g_connman->ForNode(infoMixingMasternode.addr, [&entry](CNode* pnode) {
        LogPrintf("CPrivatePayClient::RelayIn -- found master, relaying message to %s\n", pnode->addr.ToString());
        g_connman->PushMessage(pnode, NetMsgType::PPVIN, entry);
        return true;
    });
}

void CPrivatePayClient::SetState(PoolState nStateNew)
{
    LogPrintf("CPrivatePayClient::SetState -- nState: %d, nStateNew: %d\n", nState, nStateNew);
    nState = nStateNew;
}

void CPrivatePayClient::UpdatedBlockTip(const CBlockIndex *pindex)
{
    pCurrentBlockIndex = pindex;
    LogPrint("privatepay", "CPrivatePayClient::UpdatedBlockTip -- pCurrentBlockIndex->nHeight: %d\n", pCurrentBlockIndex->nHeight);

    if(!fLiteMode && masternodeSync.IsMasternodeListSynced()) {
        NewBlock();
    }

    CPrivatePay::CheckPPTXes(pindex->nHeight);
}

//TODO: Rename/move to core
void ThreadCheckPrivatePayClient(CConnman& connman)
{
    if(fLiteMode) return; // disable all Pura specific functionality

    static bool fOneThread;
    if(fOneThread) return;
    fOneThread = true;

    // Make this thread recognisable as the PrivatePay thread
    RenameThread("pura-ps-client");

    unsigned int nTick = 0;
    unsigned int nDoAutoNextRun = nTick + PRIVATEPAY_AUTO_TIMEOUT_MIN;

    while (true)
    {
        MilliSleep(1000);

        if(masternodeSync.IsBlockchainSynced() && !ShutdownRequested()) {
            nTick++;
            privatePayClient.CheckTimeout();
            if(nDoAutoNextRun == nTick) {
                privatePayClient.DoAutomaticDenominating(connman);
                nDoAutoNextRun = nTick + PRIVATEPAY_AUTO_TIMEOUT_MIN + GetRandInt(PRIVATEPAY_AUTO_TIMEOUT_MAX - PRIVATEPAY_AUTO_TIMEOUT_MIN);
            }
        }
    }
}
