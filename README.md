# EtherShield

Laboratoire de sécurité Ethereum : développer, auditer, exploiter de manière contrôlée et corriger des smart contracts Solidity.

> ⚠️ **Projet pédagogique.** Les contrats du dossier `src/vulnerable/` sont volontairement vulnérables. Ne pas les déployer sur un réseau public ni avec de vrais fonds. Toutes les expérimentations se font sur un réseau local (Anvil) avec des comptes fictifs.

## Équipe

- Zeineb chehidi
- Zeineb cheffi
- Koutouf chaabani
- Chayma bouattour

## Outils

- Anvil / Forge (Foundry) : blockchain locale et tests
- Slither : analyse statique
- OpenZeppelin : mécanismes de protection
- Solidity

## Lancer le projet

```bash
# Terminal 1 : blockchain locale
anvil

# Terminal 2 : compilation et tests
forge build
forge test
```

## Structure du dépôt

| Dossier | Contenu |
|---|---|
| `src/vulnerable/` | Contrats volontairement vulnérables |
| `src/fixed/` | Versions corrigées |
| `test/` | Tests d'exploitation et de non-régression |
| `script/` | Scripts de déploiement local |
| `reports/` | Rapports Slither et rapport d'audit |
| `docs/` | Documentation de reproduction |

## Avancement

| Faille | Contrat vulnérable | Test d'exploit | Correction | Statut |
|---|---|---|---|---|
| Reentrancy | ❌ | ❌ | ❌ | À faire |
| Access Control | ❌ | ❌ | ❌ | À faire |
| tx.origin | ❌ | ❌ | ❌ | À faire |
| Signature Replay | ❌ | ❌ | ❌ | À faire |
| Front-running / MEV | ❌ | ❌ | ❌ | À faire |
| Denial of Service | ❌ | ❌ | ❌ | À faire |
