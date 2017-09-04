// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2017 The Pura Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ppnotificationinterface.h"
#include "instapay.h"
#include "governance.h"
#include "masternodeman.h"
#include "masternode-payments.h"
#include "masternode-sync.h"
#include "privatepay-client.h"

CPPNotificationInterface::CPPNotificationInterface()
{
}

CPPNotificationInterface::~CPPNotificationInterface()
{
}

void CPPNotificationInterface::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
{
    if (fInitialDownload || pindexNew == pindexFork) // In IBD or blocks were disconnected without any new ones
     	return; 

    mnodeman.UpdatedBlockTip(pindexNew);
    privatePayClient.UpdatedBlockTip(pindexNew);
    instapay.UpdatedBlockTip(pindexNew);
    mnpayments.UpdatedBlockTip(pindexNew);
    governance.UpdatedBlockTip(pindexNew);
    masternodeSync.UpdatedBlockTip(pindexNew, fInitialDownload);
}

void CPPNotificationInterface::SyncTransaction(const CTransaction &tx, const CBlock *pblock)
{
    instapay.SyncTransaction(tx, pblock);
    CPrivatePay::SyncTransaction(tx, pblock);
}