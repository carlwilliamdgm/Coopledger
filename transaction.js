const { Horizon, Keypair, TransactionBuilder, Networks, Operation, Asset, BASE_FEE } = require('@stellar/stellar-sdk');
require('dotenv').config();

const server = new Horizon.Server('https://horizon-testnet.stellar.org');

async function enregistrerTransaction(libelle, montant) {
  const sourceKeypair = Keypair.fromSecret(process.env.SECRET_KEY);
  const sourcePublicKey = process.env.PUBLIC_KEY;

  // Charger le compte
  const account = await server.loadAccount(sourcePublicKey);

  // Construire la transaction
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(Operation.manageData({
      name: libelle.substring(0, 64),
      value: montant.toString(),
    }))
    .setTimeout(30)
    .build();

  // Signer et soumettre
  transaction.sign(sourceKeypair);
  const result = await server.submitTransaction(transaction);

  console.log('✅ Transaction enregistrée sur Stellar !');
  console.log('Hash :', result.hash);
  console.log('Voir sur : https://stellar.expert/explorer/testnet/tx/' + result.hash);
  
  return result.hash;
}

// Test — cotisation membre
// Commenté pour éviter l'exécution automatique au chargement
// enregistrerTransaction('Cotisation_Membre_001', 5000);

module.exports = {
  enregistrerTransaction,
};
