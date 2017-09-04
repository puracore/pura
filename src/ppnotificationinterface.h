// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PPNOTIFICATIONINTERFACE_H
#define BITCOIN_PPNOTIFICATIONINTERFACE_H

#include "validationinterface.h"

class CPPNotificationInterface : public CValidationInterface
{
public:
    // virtual CPPNotificationInterface();
    CPPNotificationInterface();
    virtual ~CPPNotificationInterface();

protected:
    // CValidationInterface
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload);
    void SyncTransaction(const CTransaction &tx, const CBlock *pblock);

private:
};

#endif // BITCOIN_PPNOTIFICATIONINTERFACE_H
