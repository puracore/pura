#ifndef PRIVATEPAYCONFIG_H
#define PRIVATEPAYCONFIG_H

#include <QDialog>

namespace Ui {
    class PrivatepayConfig;
}
class WalletModel;

/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class PrivatepayConfig : public QDialog
{
    Q_OBJECT

public:

    PrivatepayConfig(QWidget *parent = 0);
    ~PrivatepayConfig();

    void setModel(WalletModel *model);


private:
    Ui::PrivatepayConfig *ui;
    WalletModel *model;
    void configure(bool enabled, int coins, int rounds);

private Q_SLOTS:

    void clickBasic();
    void clickHigh();
    void clickMax();
};

#endif // PRIVATEPAYCONFIG_H
