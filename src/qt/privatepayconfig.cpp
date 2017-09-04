#include "privatepayconfig.h"
#include "ui_privatepayconfig.h"

#include "bitcoinunits.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "privatepay-client.h"
#include "walletmodel.h"

#include <QMessageBox>
#include <QPushButton>
#include <QKeyEvent>
#include <QSettings>

PrivatepayConfig::PrivatepayConfig(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PrivatepayConfig),
    model(0)
{
    ui->setupUi(this);

    connect(ui->buttonBasic, SIGNAL(clicked()), this, SLOT(clickBasic()));
    connect(ui->buttonHigh, SIGNAL(clicked()), this, SLOT(clickHigh()));
    connect(ui->buttonMax, SIGNAL(clicked()), this, SLOT(clickMax()));
}

PrivatepayConfig::~PrivatepayConfig()
{
    delete ui;
}

void PrivatepayConfig::setModel(WalletModel *model)
{
    this->model = model;
}

void PrivatepayConfig::clickBasic()
{
    configure(true, 1000, 2);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("PrivatePay Configuration"),
        tr(
            "PrivatePay was successfully set to basic (%1 and 2 rounds). You can change this at any time by opening Pura's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void PrivatepayConfig::clickHigh()
{
    configure(true, 1000, 8);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("PrivatePay Configuration"),
        tr(
            "PrivatePay was successfully set to high (%1 and 8 rounds). You can change this at any time by opening Pura's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void PrivatepayConfig::clickMax()
{
    configure(true, 1000, 16);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("PrivatePay Configuration"),
        tr(
            "PrivatePay was successfully set to maximum (%1 and 16 rounds). You can change this at any time by opening Pura's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void PrivatepayConfig::configure(bool enabled, int coins, int rounds) {

    QSettings settings;

    settings.setValue("nPrivatePayRounds", rounds);
    settings.setValue("nPrivatePayAmount", coins);

    privatePayClient.nPrivatePayRounds = rounds;
    privatePayClient.nPrivatePayAmount = coins;
}
