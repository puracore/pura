// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2017 The Pura Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "privatepay-server.h"

#include "activemasternode.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "masternode-sync.h"
#include "masternodeman.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"

CPrivatePayServer privatePayServer;

void CPrivatePayServer::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if(!fMasterNode) return;
    if(fLiteMode) return; // ignore all Pura related functionality
    if(!masternodeSync.IsBlockchainSynced()) return;

    if(strCommand == NetMsgType::PPACCEPT) {

        if(pfrom->nVersion < MIN_PRIVATEPAY_PEER_PROTO_VERSION) {
            LogPrintf("PPACCEPT -- incompatible version! nVersion: %d\n", pfrom->nVersion);
            PushStatus(pfrom, STATUS_REJECTED, ERR_VERSION);
            return;
        }

        if(IsSessionReady()) {
            // too many users in this session already, reject new ones
            LogPrintf("PPACCEPT -- queue is already full!\n");
            PushStatus(pfrom, STATUS_ACCEPTED, ERR_QUEUE_FULL);
            return;
        }

        int nDenom;
        CTransaction txCollateral;
        vRecv >> nDenom >> txCollateral;

        LogPrint("privatepay", "PPACCEPT -- nDenom %d (%s)  txCollateral %s", nDenom, CPrivatePay::GetDenominationsToString(nDenom), txCollateral.ToString());

        CMasternode* pmn = mnodeman.Find(activeMasternode.vin);
        if(pmn == NULL) {
            PushStatus(pfrom, STATUS_REJECTED, ERR_MN_LIST);
            return;
        }

        if(vecSessionCollaterals.size() == 0 && pmn->nLastDsq != 0 &&
            pmn->nLastDsq + mnodeman.CountEnabled(MIN_PRIVATEPAY_PEER_PROTO_VERSION)/5 > mnodeman.nDsqCount)
        {
            LogPrintf("PPACCEPT -- last dsq too recent, must wait: addr=%s\n", pfrom->addr.ToString());
            PushStatus(pfrom, STATUS_REJECTED, ERR_RECENT);
            return;
        }

        PoolMessage nMessageID = MSG_NOERR;

        bool fResult = nSessionID == 0  ? CreateNewSession(nDenom, txCollateral, nMessageID)
                                        : AddUserToExistingSession(nDenom, txCollateral, nMessageID);
        if(fResult) {
            LogPrintf("PPACCEPT -- is compatible, please submit!\n");
            PushStatus(pfrom, STATUS_ACCEPTED, nMessageID);
            return;
        } else {
            LogPrintf("PPACCEPT -- not compatible with existing transactions!\n");
            PushStatus(pfrom, STATUS_REJECTED, nMessageID);
            return;
        }

    } else if(strCommand == NetMsgType::PPQUEUE) {
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

        CMasternode* pmn = mnodeman.Find(dsq.vin);
        if(pmn == NULL) return;

        if(!dsq.CheckSignature(pmn->pubKeyMasternode)) {
            // we probably have outdated info
            mnodeman.AskForMN(pfrom, dsq.vin);
            return;
        }

        if(!dsq.fReady) {
            BOOST_FOREACH(CPrivatepayQueue q, vecPrivatepayQueue) {
                if(q.vin == dsq.vin) {
                    // no way same mn can send another "not yet ready" dsq this soon
                    LogPrint("privatepay", "PPQUEUE -- Masternode %s is sending WAY too many dsq messages\n", pmn->addr.ToString());
                    return;
                }
            }

            int nThreshold = pmn->nLastDsq + mnodeman.CountEnabled(MIN_PRIVATEPAY_PEER_PROTO_VERSION)/5;
            LogPrint("privatepay", "PPQUEUE -- nLastDsq: %d  threshold: %d  nDsqCount: %d\n", pmn->nLastDsq, nThreshold, mnodeman.nDsqCount);
            //don't allow a few nodes to dominate the queuing process
            if(pmn->nLastDsq != 0 && nThreshold > mnodeman.nDsqCount) {
                LogPrint("privatepay", "PPQUEUE -- Masternode %s is sending too many dsq messages\n", pmn->addr.ToString());
                return;
            }
            mnodeman.nDsqCount++;
            pmn->nLastDsq = mnodeman.nDsqCount;
            pmn->fAllowMixingTx = true;

            LogPrint("privatepay", "PPQUEUE -- new PrivatePay queue (%s) from masternode %s\n", dsq.ToString(), pmn->addr.ToString());
            vecPrivatepayQueue.push_back(dsq);
            dsq.Relay();
        }

    } else if(strCommand == NetMsgType::PPVIN) {

        if(pfrom->nVersion < MIN_PRIVATEPAY_PEER_PROTO_VERSION) {
            LogPrintf("PPVIN -- incompatible version! nVersion: %d\n", pfrom->nVersion);
            PushStatus(pfrom, STATUS_REJECTED, ERR_VERSION);
            return;
        }

        //do we have enough users in the current session?
        if(!IsSessionReady()) {
            LogPrintf("PPVIN -- session not complete!\n");
            PushStatus(pfrom, STATUS_REJECTED, ERR_SESSION);
            return;
        }

        CPrivatePayEntry entry;
        vRecv >> entry;

        LogPrint("privatepay", "PPVIN -- txCollateral %s", entry.txCollateral.ToString());

        if(entry.vecTxDSIn.size() > PRIVATEPAY_ENTRY_MAX_SIZE) {
            LogPrintf("PPVIN -- ERROR: too many inputs! %d/%d\n", entry.vecTxDSIn.size(), PRIVATEPAY_ENTRY_MAX_SIZE);
            PushStatus(pfrom, STATUS_REJECTED, ERR_MAXIMUM);
            return;
        }

        if(entry.vecTxDSOut.size() > PRIVATEPAY_ENTRY_MAX_SIZE) {
            LogPrintf("PPVIN -- ERROR: too many outputs! %d/%d\n", entry.vecTxDSOut.size(), PRIVATEPAY_ENTRY_MAX_SIZE);
            PushStatus(pfrom, STATUS_REJECTED, ERR_MAXIMUM);
            return;
        }

        //do we have the same denominations as the current session?
        if(!IsOutputsCompatibleWithSessionDenom(entry.vecTxDSOut)) {
            LogPrintf("PPVIN -- not compatible with existing transactions!\n");
            PushStatus(pfrom, STATUS_REJECTED, ERR_EXISTING_TX);
            return;
        }

        //check it like a transaction
        {
            CAmount nValueIn = 0;
            CAmount nValueOut = 0;

            CMutableTransaction tx;

            BOOST_FOREACH(const CTxOut txout, entry.vecTxDSOut) {
                nValueOut += txout.nValue;
                tx.vout.push_back(txout);

                if(txout.scriptPubKey.size() != 25) {
                    LogPrintf("PPVIN -- non-standard pubkey detected! scriptPubKey=%s\n", ScriptToAsmStr(txout.scriptPubKey));
                    PushStatus(pfrom, STATUS_REJECTED, ERR_NON_STANDARD_PUBKEY);
                    return;
                }
                if(!txout.scriptPubKey.IsNormalPaymentScript()) {
                    LogPrintf("PPVIN -- invalid script! scriptPubKey=%s\n", ScriptToAsmStr(txout.scriptPubKey));
                    PushStatus(pfrom, STATUS_REJECTED, ERR_INVALID_SCRIPT);
                    return;
                }
            }

            BOOST_FOREACH(const CTxIn txin, entry.vecTxDSIn) {
                tx.vin.push_back(txin);

                LogPrint("privatepay", "PPVIN -- txin=%s\n", txin.ToString());

                CTransaction txPrev;
                uint256 hash;
                if(GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), hash, true)) {
                    if(txPrev.vout.size() > txin.prevout.n)
                        nValueIn += txPrev.vout[txin.prevout.n].nValue;
                } else {
                    LogPrintf("PPVIN -- missing input! tx=%s", tx.ToString());
                    PushStatus(pfrom, STATUS_REJECTED, ERR_MISSING_TX);
                    return;
                }
            }

            // There should be no fee in mixing tx
            CAmount nFee = nValueIn - nValueOut;
            if(nFee != 0) {
                LogPrintf("PPVIN -- there should be no fee in mixing tx! fees: %lld, tx=%s", nFee, tx.ToString());
                PushStatus(pfrom, STATUS_REJECTED, ERR_FEES);
                return;
            }

            {
                LOCK(cs_main);
                CValidationState validationState;
                mempool.PrioritiseTransaction(tx.GetHash(), tx.GetHash().ToString(), 1000, 0.1*COIN);
                if(!AcceptToMemoryPool(mempool, validationState, CTransaction(tx), false, NULL, false, true, true)) {
                    LogPrintf("PPVIN -- transaction not valid! tx=%s", tx.ToString());
                    PushStatus(pfrom, STATUS_REJECTED, ERR_INVALID_TX);
                    return;
                }
            }
        }

        PoolMessage nMessageID = MSG_NOERR;

        entry.addr = pfrom->addr;
        if(AddEntry(entry, nMessageID)) {
            PushStatus(pfrom, STATUS_ACCEPTED, nMessageID);
            CheckPool();
            RelayStatus(STATUS_ACCEPTED);
        } else {
            PushStatus(pfrom, STATUS_REJECTED, nMessageID);
            SetNull();
        }

    } else if(strCommand == NetMsgType::PPSIGNFINALTX) {

        if(pfrom->nVersion < MIN_PRIVATEPAY_PEER_PROTO_VERSION) {
            LogPrintf("PPSIGNFINALTX -- incompatible version! nVersion: %d\n", pfrom->nVersion);
            return;
        }

        std::vector<CTxIn> vecTxIn;
        vRecv >> vecTxIn;

        LogPrint("privatepay", "PPSIGNFINALTX -- vecTxIn.size() %s\n", vecTxIn.size());

        int nTxInIndex = 0;
        int nTxInsCount = (int)vecTxIn.size();

        BOOST_FOREACH(const CTxIn txin, vecTxIn) {
            nTxInIndex++;
            if(!AddScriptSig(txin)) {
                LogPrint("privatepay", "PPSIGNFINALTX -- AddScriptSig() failed at %d/%d, session: %d\n", nTxInIndex, nTxInsCount, nSessionID);
                RelayStatus(STATUS_REJECTED);
                return;
            }
            LogPrint("privatepay", "PPSIGNFINALTX -- AddScriptSig() %d/%d success\n", nTxInIndex, nTxInsCount);
        }
        // all is good
        CheckPool();
    }
}

void CPrivatePayServer::SetNull()
{
    // MN side
    vecSessionCollaterals.clear();

    CPrivatePayBase::SetNull();
}

//
// Check the mixing progress and send client updates if a Masternode
//
void CPrivatePayServer::CheckPool()
{
    if(fMasterNode) {
        LogPrint("privatepay", "CPrivatePayServer::CheckPool -- entries count %lu\n", GetEntriesCount());

        // If entries are full, create finalized transaction
        if(nState == POOL_STATE_ACCEPTING_ENTRIES && GetEntriesCount() >= CPrivatePay::GetMaxPoolTransactions()) {
            LogPrint("privatepay", "CPrivatePayServer::CheckPool -- FINALIZE TRANSACTIONS\n");
            CreateFinalTransaction();
            return;
        }

        // If we have all of the signatures, try to compile the transaction
        if(nState == POOL_STATE_SIGNING && IsSignaturesComplete()) {
            LogPrint("privatepay", "CPrivatePayServer::CheckPool -- SIGNING\n");
            CommitFinalTransaction();
            return;
        }
    }

    // reset if we're here for 10 seconds
    if((nState == POOL_STATE_ERROR || nState == POOL_STATE_SUCCESS) && GetTimeMillis() - nTimeLastSuccessfulStep >= 10000) {
        LogPrint("privatepay", "CPrivatePayServer::CheckPool -- timeout, RESETTING\n");
        SetNull();
    }
}

void CPrivatePayServer::CreateFinalTransaction()
{
    LogPrint("privatepay", "CPrivatePayServer::CreateFinalTransaction -- FINALIZE TRANSACTIONS\n");

    CMutableTransaction txNew;

    // make our new transaction
    for(int i = 0; i < GetEntriesCount(); i++) {
        BOOST_FOREACH(const CTxDSOut& txdsout, vecEntries[i].vecTxDSOut)
            txNew.vout.push_back(txdsout);

        BOOST_FOREACH(const CTxDSIn& txdsin, vecEntries[i].vecTxDSIn)
            txNew.vin.push_back(txdsin);
    }

    sort(txNew.vin.begin(), txNew.vin.end(), CompareInputBIP69());
    sort(txNew.vout.begin(), txNew.vout.end(), CompareOutputBIP69());

    finalMutableTransaction = txNew;
    LogPrint("privatepay", "CPrivatePayServer::CreateFinalTransaction -- finalMutableTransaction=%s", txNew.ToString());

    // request signatures from clients
    RelayFinalTransaction(finalMutableTransaction);
    SetState(POOL_STATE_SIGNING);
}

void CPrivatePayServer::CommitFinalTransaction()
{
    if(!fMasterNode) return; // check and relay final tx only on masternode

    CTransaction finalTransaction = CTransaction(finalMutableTransaction);
    uint256 hashTx = finalTransaction.GetHash();

    LogPrint("privatepay", "CPrivatePayServer::CommitFinalTransaction -- finalTransaction=%s", finalTransaction.ToString());

    {
        // See if the transaction is valid
        TRY_LOCK(cs_main, lockMain);
        CValidationState validationState;
        mempool.PrioritiseTransaction(hashTx, hashTx.ToString(), 1000, 0.1*COIN);
        if(!lockMain || !AcceptToMemoryPool(mempool, validationState, finalTransaction, false, NULL, false, true, true))
        {
            LogPrintf("CPrivatePayServer::CommitFinalTransaction -- AcceptToMemoryPool() error: Transaction not valid\n");
            SetNull();
            // not much we can do in this case, just notify clients
            RelayCompletedTransaction(ERR_INVALID_TX);
            return;
        }
    }

    LogPrintf("CPrivatePayServer::CommitFinalTransaction -- CREATING PPTX\n");

    // create and sign masternode pptx transaction
    if(!CPrivatePay::GetPPTX(hashTx)) {
        CPrivatepayBroadcastTx pptxNew(finalTransaction, activeMasternode.vin, GetAdjustedTime());
        pptxNew.Sign();
        CPrivatePay::AddPPTX(pptxNew);
    }

    LogPrintf("CPrivatePayServer::CommitFinalTransaction -- TRANSMITTING PPTX\n");

    CInv inv(MSG_PPTX, hashTx);
    g_connman->RelayInv(inv);

    // Tell the clients it was successful
    RelayCompletedTransaction(MSG_SUCCESS);

    // Randomly charge clients
    ChargeRandomFees();

    // Reset
    LogPrint("privatepay", "CPrivatePayServer::CommitFinalTransaction -- COMPLETED -- RESETTING\n");
    SetNull();
}

//
// Charge clients a fee if they're abusive
//
// Why bother? PrivatePay uses collateral to ensure abuse to the process is kept to a minimum.
// The submission and signing stages are completely separate. In the cases where
// a client submits a transaction then refused to sign, there must be a cost. Otherwise they
// would be able to do this over and over again and bring the mixing to a hault.
//
// How does this work? Messages to Masternodes come in via NetMsgType::PPVIN, these require a valid collateral
// transaction for the client to be able to enter the pool. This transaction is kept by the Masternode
// until the transaction is either complete or fails.
//
void CPrivatePayServer::ChargeFees()
{
    if(!fMasterNode) return;

    //we don't need to charge collateral for every offence.
    if(GetRandInt(100) > 33) return;

    std::vector<CTransaction> vecOffendersCollaterals;

    if(nState == POOL_STATE_ACCEPTING_ENTRIES) {
        BOOST_FOREACH(const CTransaction& txCollateral, vecSessionCollaterals) {
            bool fFound = false;
            BOOST_FOREACH(const CPrivatePayEntry& entry, vecEntries)
                if(entry.txCollateral == txCollateral)
                    fFound = true;

            // This queue entry didn't send us the promised transaction
            if(!fFound) {
                LogPrintf("CPrivatePayServer::ChargeFees -- found uncooperative node (didn't send transaction), found offence\n");
                vecOffendersCollaterals.push_back(txCollateral);
            }
        }
    }

    if(nState == POOL_STATE_SIGNING) {
        // who didn't sign?
        BOOST_FOREACH(const CPrivatePayEntry entry, vecEntries) {
            BOOST_FOREACH(const CTxDSIn txdsin, entry.vecTxDSIn) {
                if(!txdsin.fHasSig) {
                    LogPrintf("CPrivatePayServer::ChargeFees -- found uncooperative node (didn't sign), found offence\n");
                    vecOffendersCollaterals.push_back(entry.txCollateral);
                }
            }
        }
    }

    // no offences found
    if(vecOffendersCollaterals.empty()) return;

    //mostly offending? Charge sometimes
    if((int)vecOffendersCollaterals.size() >= Params().PoolMaxTransactions() - 1 && GetRandInt(100) > 33) return;

    //everyone is an offender? That's not right
    if((int)vecOffendersCollaterals.size() >= Params().PoolMaxTransactions()) return;

    //charge one of the offenders randomly
    std::random_shuffle(vecOffendersCollaterals.begin(), vecOffendersCollaterals.end());

    if(nState == POOL_STATE_ACCEPTING_ENTRIES || nState == POOL_STATE_SIGNING) {
        LogPrintf("CPrivatePayServer::ChargeFees -- found uncooperative node (didn't %s transaction), charging fees: %s\n",
                (nState == POOL_STATE_SIGNING) ? "sign" : "send", vecOffendersCollaterals[0].ToString());

        LOCK(cs_main);

        CValidationState state;
        bool fMissingInputs;
        if(!AcceptToMemoryPool(mempool, state, vecOffendersCollaterals[0], false, &fMissingInputs, false, true)) {
            // should never really happen
            LogPrintf("CPrivatePayServer::ChargeFees -- ERROR: AcceptToMemoryPool failed!\n");
        } else {
            g_connman->RelayTransaction(vecOffendersCollaterals[0]);
        }
    }
}

/*
    Charge the collateral randomly.
    Mixing is completely free, to pay miners we randomly pay the collateral of users.

    Collateral Fee Charges:

    Being that mixing has "no fees" we need to have some kind of cost associated
    with using it to stop abuse. Otherwise it could serve as an attack vector and
    allow endless transaction that would bloat Pura and make it unusable. To
    stop these kinds of attacks 1 in 10 successful transactions are charged. This
    adds up to a cost of 0.001 PURA per transaction on average.
*/
void CPrivatePayServer::ChargeRandomFees()
{
    if(!fMasterNode) return;

    LOCK(cs_main);

    BOOST_FOREACH(const CTransaction& txCollateral, vecSessionCollaterals) {

        if(GetRandInt(100) > 10) return;

        LogPrintf("CPrivatePayServer::ChargeRandomFees -- charging random fees, txCollateral=%s", txCollateral.ToString());

        CValidationState state;
        bool fMissingInputs;
        if(!AcceptToMemoryPool(mempool, state, txCollateral, false, &fMissingInputs, false, true)) {
            // should never really happen
            LogPrintf("CPrivatePayServer::ChargeRandomFees -- ERROR: AcceptToMemoryPool failed!\n");
        } else {
            g_connman->RelayTransaction(txCollateral);
        }
    }
}

//
// Check for various timeouts (queue objects, mixing, etc)
//
void CPrivatePayServer::CheckTimeout()
{
    {
        TRY_LOCK(cs_privatepay, lockDS);
        if(!lockDS) return; // it's ok to fail here, we run this quite frequently

        // check mixing queue objects for timeouts
        std::vector<CPrivatepayQueue>::iterator it = vecPrivatepayQueue.begin();
        while(it != vecPrivatepayQueue.end()) {
            if((*it).IsExpired()) {
                LogPrint("privatepay", "CPrivatePayServer::CheckTimeout -- Removing expired queue (%s)\n", (*it).ToString());
                it = vecPrivatepayQueue.erase(it);
            } else ++it;
        }
    }

    if(!fMasterNode) return;

    int nLagTime = fMasterNode ? 0 : 10000; // if we're the client, give the server a few extra seconds before resetting.
    int nTimeout = (nState == POOL_STATE_SIGNING) ? PRIVATEPAY_SIGNING_TIMEOUT : PRIVATEPAY_QUEUE_TIMEOUT;
    bool fTimeout = GetTimeMillis() - nTimeLastSuccessfulStep >= nTimeout*1000 + nLagTime;

    if(nState != POOL_STATE_IDLE && fTimeout) {
        LogPrint("privatepay", "CPrivatePayServer::CheckTimeout -- %s timed out (%ds) -- restting\n",
                (nState == POOL_STATE_SIGNING) ? "Signing" : "Session", nTimeout);
        ChargeFees();
        SetNull();
        SetState(POOL_STATE_ERROR);
    }
}

/*
    Check to see if we're ready for submissions from clients
    After receiving multiple dsa messages, the queue will switch to "accepting entries"
    which is the active state right before merging the transaction
*/
void CPrivatePayServer::CheckForCompleteQueue()
{
    if(!fMasterNode) return;

    if(nState == POOL_STATE_QUEUE && IsSessionReady()) {
        SetState(POOL_STATE_ACCEPTING_ENTRIES);

        CPrivatepayQueue dsq(nSessionDenom, activeMasternode.vin, GetTime(), true);
        LogPrint("privatepay", "CPrivatePayServer::CheckForCompleteQueue -- queue is ready, signing and relaying (%s)\n", dsq.ToString());
        dsq.Sign();
        dsq.Relay();
    }
}

// Check to make sure a given input matches an input in the pool and its scriptSig is valid
bool CPrivatePayServer::IsInputScriptSigValid(const CTxIn& txin)
{
    CMutableTransaction txNew;
    txNew.vin.clear();
    txNew.vout.clear();

    int i = 0;
    int nTxInIndex = -1;
    CScript sigPubKey = CScript();

    BOOST_FOREACH(CPrivatePayEntry& entry, vecEntries) {

        BOOST_FOREACH(const CTxDSOut& txdsout, entry.vecTxDSOut)
            txNew.vout.push_back(txdsout);

        BOOST_FOREACH(const CTxDSIn& txdsin, entry.vecTxDSIn) {
            txNew.vin.push_back(txdsin);

            if(txdsin.prevout == txin.prevout) {
                nTxInIndex = i;
                sigPubKey = txdsin.prevPubKey;
            }
            i++;
        }
    }

    if(nTxInIndex >= 0) { //might have to do this one input at a time?
        txNew.vin[nTxInIndex].scriptSig = txin.scriptSig;
        LogPrint("privatepay", "CPrivatePayServer::IsInputScriptSigValid -- verifying scriptSig %s\n", ScriptToAsmStr(txin.scriptSig).substr(0,24));
        if(!VerifyScript(txNew.vin[nTxInIndex].scriptSig, sigPubKey, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC, MutableTransactionSignatureChecker(&txNew, nTxInIndex))) {
            LogPrint("privatepay", "CPrivatePayServer::IsInputScriptSigValid -- VerifyScript() failed on input %d\n", nTxInIndex);
            return false;
        }
    } else {
        LogPrint("privatepay", "CPrivatePayServer::IsInputScriptSigValid -- Failed to find matching input in pool, %s\n", txin.ToString());
        return false;
    }

    LogPrint("privatepay", "CPrivatePayServer::IsInputScriptSigValid -- Successfully validated input and scriptSig\n");
    return true;
}

//
// Add a clients transaction to the pool
//
bool CPrivatePayServer::AddEntry(const CPrivatePayEntry& entryNew, PoolMessage& nMessageIDRet)
{
    if(!fMasterNode) return false;

    BOOST_FOREACH(CTxIn txin, entryNew.vecTxDSIn) {
        if(txin.prevout.IsNull()) {
            LogPrint("privatepay", "CPrivatePayServer::AddEntry -- input not valid!\n");
            nMessageIDRet = ERR_INVALID_INPUT;
            return false;
        }
    }

    if(!CPrivatePay::IsCollateralValid(entryNew.txCollateral)) {
        LogPrint("privatepay", "CPrivatePayServer::AddEntry -- collateral not valid!\n");
        nMessageIDRet = ERR_INVALID_COLLATERAL;
        return false;
    }

    if(GetEntriesCount() >= CPrivatePay::GetMaxPoolTransactions()) {
        LogPrint("privatepay", "CPrivatePayServer::AddEntry -- entries is full!\n");
        nMessageIDRet = ERR_ENTRIES_FULL;
        return false;
    }

    BOOST_FOREACH(CTxIn txin, entryNew.vecTxDSIn) {
        LogPrint("privatepay", "looking for txin -- %s\n", txin.ToString());
        BOOST_FOREACH(const CPrivatePayEntry& entry, vecEntries) {
            BOOST_FOREACH(const CTxDSIn& txdsin, entry.vecTxDSIn) {
                if(txdsin.prevout == txin.prevout) {
                    LogPrint("privatepay", "CPrivatePayServer::AddEntry -- found in txin\n");
                    nMessageIDRet = ERR_ALREADY_HAVE;
                    return false;
                }
            }
        }
    }

    vecEntries.push_back(entryNew);

    LogPrint("privatepay", "CPrivatePayServer::AddEntry -- adding entry\n");
    nMessageIDRet = MSG_ENTRIES_ADDED;
    nTimeLastSuccessfulStep = GetTimeMillis();

    return true;
}

bool CPrivatePayServer::AddScriptSig(const CTxIn& txinNew)
{
    LogPrint("privatepay", "CPrivatePayServer::AddScriptSig -- scriptSig=%s\n", ScriptToAsmStr(txinNew.scriptSig).substr(0,24));

    BOOST_FOREACH(const CPrivatePayEntry& entry, vecEntries) {
        BOOST_FOREACH(const CTxDSIn& txdsin, entry.vecTxDSIn) {
            if(txdsin.scriptSig == txinNew.scriptSig) {
                LogPrint("privatepay", "CPrivatePayServer::AddScriptSig -- already exists\n");
                return false;
            }
        }
    }

    if(!IsInputScriptSigValid(txinNew)) {
        LogPrint("privatepay", "CPrivatePayServer::AddScriptSig -- Invalid scriptSig\n");
        return false;
    }

    LogPrint("privatepay", "CPrivatePayServer::AddScriptSig -- scriptSig=%s new\n", ScriptToAsmStr(txinNew.scriptSig).substr(0,24));

    BOOST_FOREACH(CTxIn& txin, finalMutableTransaction.vin) {
        if(txinNew.prevout == txin.prevout && txin.nSequence == txinNew.nSequence) {
            txin.scriptSig = txinNew.scriptSig;
            txin.prevPubKey = txinNew.prevPubKey;
            LogPrint("privatepay", "CPrivatePayServer::AddScriptSig -- adding to finalMutableTransaction, scriptSig=%s\n", ScriptToAsmStr(txinNew.scriptSig).substr(0,24));
        }
    }
    for(int i = 0; i < GetEntriesCount(); i++) {
        if(vecEntries[i].AddScriptSig(txinNew)) {
            LogPrint("privatepay", "CPrivatePayServer::AddScriptSig -- adding to entries, scriptSig=%s\n", ScriptToAsmStr(txinNew.scriptSig).substr(0,24));
            return true;
        }
    }

    LogPrintf("CPrivatePayServer::AddScriptSig -- Couldn't set sig!\n" );
    return false;
}

// Check to make sure everything is signed
bool CPrivatePayServer::IsSignaturesComplete()
{
    BOOST_FOREACH(const CPrivatePayEntry& entry, vecEntries)
        BOOST_FOREACH(const CTxDSIn& txdsin, entry.vecTxDSIn)
            if(!txdsin.fHasSig) return false;

    return true;
}

bool CPrivatePayServer::IsOutputsCompatibleWithSessionDenom(const std::vector<CTxDSOut>& vecTxDSOut)
{
    if(CPrivatePay::GetDenominations(vecTxDSOut) == 0) return false;

    BOOST_FOREACH(const CPrivatePayEntry entry, vecEntries) {
        LogPrintf("CPrivatePayServer::IsOutputsCompatibleWithSessionDenom -- vecTxDSOut denom %d, entry.vecTxDSOut denom %d\n",
                CPrivatePay::GetDenominations(vecTxDSOut), CPrivatePay::GetDenominations(entry.vecTxDSOut));
        if(CPrivatePay::GetDenominations(vecTxDSOut) != CPrivatePay::GetDenominations(entry.vecTxDSOut)) return false;
    }

    return true;
}

bool CPrivatePayServer::IsAcceptableDenomAndCollateral(int nDenom, CTransaction txCollateral, PoolMessage& nMessageIDRet)
{
    if(!fMasterNode) return false;

    // is denom even smth legit?
    std::vector<int> vecBits;
    if(!CPrivatePay::GetDenominationsBits(nDenom, vecBits)) {
        LogPrint("privatepay", "CPrivatePayServer::IsAcceptableDenomAndCollateral -- denom not valid!\n");
        nMessageIDRet = ERR_DENOM;
        return false;
    }

    // check collateral
    if(!fUnitTest && !CPrivatePay::IsCollateralValid(txCollateral)) {
        LogPrint("privatepay", "CPrivatePayServer::IsAcceptableDenomAndCollateral -- collateral not valid!\n");
        nMessageIDRet = ERR_INVALID_COLLATERAL;
        return false;
    }

    return true;
}

bool CPrivatePayServer::CreateNewSession(int nDenom, CTransaction txCollateral, PoolMessage& nMessageIDRet)
{
    if(!fMasterNode || nSessionID != 0) return false;

    // new session can only be started in idle mode
    if(nState != POOL_STATE_IDLE) {
        nMessageIDRet = ERR_MODE;
        LogPrintf("CPrivatePayServer::CreateNewSession -- incompatible mode: nState=%d\n", nState);
        return false;
    }

    if(!IsAcceptableDenomAndCollateral(nDenom, txCollateral, nMessageIDRet)) {
        return false;
    }

    // start new session
    nMessageIDRet = MSG_NOERR;
    nSessionID = GetRandInt(999999)+1;
    nSessionDenom = nDenom;

    SetState(POOL_STATE_QUEUE);
    nTimeLastSuccessfulStep = GetTimeMillis();

    if(!fUnitTest) {
        //broadcast that I'm accepting entries, only if it's the first entry through
        CPrivatepayQueue dsq(nDenom, activeMasternode.vin, GetTime(), false);
        LogPrint("privatepay", "CPrivatePayServer::CreateNewSession -- signing and relaying new queue: %s\n", dsq.ToString());
        dsq.Sign();
        dsq.Relay();
        vecPrivatepayQueue.push_back(dsq);
    }

    vecSessionCollaterals.push_back(txCollateral);
    LogPrintf("CPrivatePayServer::CreateNewSession -- new session created, nSessionID: %d  nSessionDenom: %d (%s)  vecSessionCollaterals.size(): %d\n",
            nSessionID, nSessionDenom, CPrivatePay::GetDenominationsToString(nSessionDenom), vecSessionCollaterals.size());

    return true;
}

bool CPrivatePayServer::AddUserToExistingSession(int nDenom, CTransaction txCollateral, PoolMessage& nMessageIDRet)
{
    if(!fMasterNode || nSessionID == 0 || IsSessionReady()) return false;

    if(!IsAcceptableDenomAndCollateral(nDenom, txCollateral, nMessageIDRet)) {
        return false;
    }

    // we only add new users to an existing session when we are in queue mode
    if(nState != POOL_STATE_QUEUE) {
        nMessageIDRet = ERR_MODE;
        LogPrintf("CPrivatePayServer::AddUserToExistingSession -- incompatible mode: nState=%d\n", nState);
        return false;
    }

    if(nDenom != nSessionDenom) {
        LogPrintf("CPrivatePayServer::AddUserToExistingSession -- incompatible denom %d (%s) != nSessionDenom %d (%s)\n",
                    nDenom, CPrivatePay::GetDenominationsToString(nDenom), nSessionDenom, CPrivatePay::GetDenominationsToString(nSessionDenom));
        nMessageIDRet = ERR_DENOM;
        return false;
    }

    // count new user as accepted to an existing session

    nMessageIDRet = MSG_NOERR;
    nTimeLastSuccessfulStep = GetTimeMillis();
    vecSessionCollaterals.push_back(txCollateral);

    LogPrintf("CPrivatePayServer::AddUserToExistingSession -- new user accepted, nSessionID: %d  nSessionDenom: %d (%s)  vecSessionCollaterals.size(): %d\n",
            nSessionID, nSessionDenom, CPrivatePay::GetDenominationsToString(nSessionDenom), vecSessionCollaterals.size());

    return true;
}

void CPrivatePayServer::RelayFinalTransaction(const CTransaction& txFinal)
{
    LogPrint("privatepay", "CPrivatePayServer::%s -- nSessionID: %d  nSessionDenom: %d (%s)\n",
            __func__, nSessionID, nSessionDenom, CPrivatePay::GetDenominationsToString(nSessionDenom));

    // final mixing tx with empty signatures should be relayed to mixing participants only
    for (const auto entry : vecEntries) {
        bool fOk = g_connman->ForNode(entry.addr, [&txFinal, this](CNode* pnode) {
            g_connman->PushMessage(pnode, NetMsgType::PPFINALTX, nSessionID, txFinal);
            return true;
        });
        if(!fOk) {
            // no such node? maybe this client disconnected or our own connection went down
            RelayStatus(STATUS_REJECTED);
            break;
        }
    }
}

void CPrivatePayServer::PushStatus(CNode* pnode, PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID)
{
    if(!pnode) return;
    g_connman->PushMessage(pnode, NetMsgType::PPSTATUSUPDATE, nSessionID, (int)nState, (int)vecEntries.size(), (int)nStatusUpdate, (int)nMessageID);
}

void CPrivatePayServer::RelayStatus(PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID)
{
    unsigned int nDisconnected{};
    // status updates should be relayed to mixing participants only
    for (const auto entry : vecEntries) {
        // make sure everyone is still connected
        bool fOk = g_connman->ForNode(entry.addr, [&nStatusUpdate, &nMessageID, this](CNode* pnode) {
            PushStatus(pnode, nStatusUpdate, nMessageID);
            return true;
        });
        if(!fOk) {
            // no such node? maybe this client disconnected or our own connection went down
            ++nDisconnected;
        }
    }
    if (nDisconnected == 0) return; // all is clear

    // smth went wrong
    LogPrintf("CPrivatePayServer::%s -- can't continue, %llu client(s) disconnected, nSessionID: %d  nSessionDenom: %d (%s)\n",
            __func__, nDisconnected, nSessionID, nSessionDenom, CPrivatePay::GetDenominationsToString(nSessionDenom));

    // notify everyone else that this session should be terminated
    for (const auto entry : vecEntries) {
        g_connman->ForNode(entry.addr, [this](CNode* pnode) {
            PushStatus(pnode, STATUS_REJECTED, MSG_NOERR);
            return true;
        });
    }

    if(nDisconnected == vecEntries.size()) {
        // all clients disconnected, there is probably some issues with our own connection
        // do not charge any fees, just reset the pool
        SetNull();
    }
}

void CPrivatePayServer::RelayCompletedTransaction(PoolMessage nMessageID)
{
    LogPrint("privatepay", "CPrivatePayServer::%s -- nSessionID: %d  nSessionDenom: %d (%s)\n",
            __func__, nSessionID, nSessionDenom, CPrivatePay::GetDenominationsToString(nSessionDenom));

    // final mixing tx with empty signatures should be relayed to mixing participants only
    for (const auto entry : vecEntries) {
        bool fOk = g_connman->ForNode(entry.addr, [&nMessageID, this](CNode* pnode) {
            g_connman->PushMessage(pnode, NetMsgType::PPCOMPLETE, nSessionID, (int)nMessageID);
            return true;
        });
        if(!fOk) {
            // no such node? maybe client disconnected or our own connection went down
            RelayStatus(STATUS_REJECTED);
            break;
        }
    }
}

void CPrivatePayServer::SetState(PoolState nStateNew)
{
    if(fMasterNode && (nStateNew == POOL_STATE_ERROR || nStateNew == POOL_STATE_SUCCESS)) {
        LogPrint("privatepay", "CPrivatePayServer::SetState -- Can't set state to ERROR or SUCCESS as a Masternode. \n");
        return;
    }

    LogPrintf("CPrivatePayServer::SetState -- nState: %d, nStateNew: %d\n", nState, nStateNew);
    nState = nStateNew;
}

//TODO: Rename/move to core
void ThreadCheckPrivatePayServer()
{
    if(fLiteMode) return; // disable all Pura specific functionality

    static bool fOneThread;
    if(fOneThread) return;
    fOneThread = true;

    // Make this thread recognisable as the PrivatePay thread
    RenameThread("pura-ps-server");

    unsigned int nTick = 0;

    while (true)
    {
        MilliSleep(1000);

        if(masternodeSync.IsBlockchainSynced() && !ShutdownRequested()) {
            nTick++;
            privatePayServer.CheckTimeout();
            privatePayServer.CheckForCompleteQueue();
        }
    }
}
