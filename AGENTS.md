# AGENTS.md — vyvil-core

Before working on this project, read `.specdd/bootstrap.md`, then `.specdd/bootstrap.project.md`.

Assume the role, rules, workflow, and implementation constraints described in SpecDD. Treat
SpecDD specs as source-adjacent development contracts, not optional documentation. Adhere to
SpecDD rules unless explicitly instructed otherwise.

## Projet

Crate Rust générique (Rhai + Handlebars, handlers K8s/OCI/S3 optionnels), extraite du
workspace [vynil](https://github.com/sebt3/vynil) pour être réutilisable par d'autres projets
(kuberest, kydah, …). Publiée sur crates.io, API instable (< 1.0). Licence BSD 3-Clause.

## Flux de travail : SpecDD + test-first

`Spec approuvée → tests depuis les Scenario → implémentation minimale → validation → [x]`.
Détail complet dans `.specdd/bootstrap.project.md`. Règles clés :

- Une spec `.sdd` par fichier de `src/` (groupe 2–3 fichiers seulement si un seul contrat —
  un `*_mock.rs` avec sa source), décrivant tout le comportement du fichier.
- La documentation a sa spec racine propre : `docs.sdd` `Owns` `./docs/` (trois pages) et
  `./README.md`. Une page ne contracte rien : en cas de divergence, la spec du module fait foi
  et la correction est une tâche de `docs.sdd`.
- CI et harnais outil ont leurs propres specs : `.github/workflows/workflows.sdd`,
  `tooling.sdd`, spec racine `vyvil-core.sdd`.
- **Reconciliation à la clôture** : une tâche qui change un comportement oblige à reprendre les
  sections descriptives de sa spec (`Exposes`, `Accepts`, `Handles`, `Raises`) à l'état que le
  contrat produit. Un `Must` amendé ne tient pas lieu de mise à jour de ce qui décrit l'avant.
- **Autonomie de chaînage** (décision du développeur principal) : une tâche déjà inscrite dans
  une spec claire, en périmètre `Owns`, se déroule sans go préalable — tests d'abord,
  implémentation minimale, validation, `[x]`. On revient vers lui sur un doute de contrat, une
  frontière à trancher, ou une incertitude remontée par un agent — pas à chaque lot.
- Jamais de tâche `[x]` sans synthèse du `validator` au vert.
- **Bijection spec ↔ code** : un fichier n'est écrit que sous l'autorité de la spec dont
  l'`Owns` le nomme, ou d'une `Can modify` qu'elle déclare. Une tâche qui déborde du fichier
  qu'elle spécifie est inscrite dans les `Tasks:` de la spec propriétaire de ce fichier ;
  l'originale ne garde que sa part en périmètre, nomme sa jumelle, et les deux se cochent dans
  le même commit (une face publique changée ailleurs casse la compilation). Un artefact sans
  `Owns` n'est pas une zone libre : le remède est l'attribution, jamais la tolérance. Les
  trois pages de `./docs/` et `./README.md` appartiennent à `docs.sdd` depuis leur
  attribution ; un artefact redevenu sans propriétaire est un trou à boucher avant toute
  tâche le visant.

## Harnais clippy

`Cargo.toml` `[lints]` porte le harnais (contractualisé par `tooling.sdd`) : `unsafe_code`
interdit, `missing_docs` warn, `pedantic` + `cargo` et la famille stricte
(`unwrap_used`, `expect_used`, `panic`, `unreachable`, `dbg_macro`, `todo`, `unimplemented`,
`print_stdout`, `print_stderr`, `arithmetic_side_effects`) en `deny` depuis la purge de dette.
Seul `multiple_crate_versions` (doublons de versions des dépendances amont) est `allow`.
En production : aucun
`unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!`/`dbg!`/`println!`.

## Agents (`.opencode/agents/`)

| Agent | Rôle |
|---|---|
| `spec-dd` (primary) | Rédige les specs avec Sébastien, orchestre les sous-agents, ne code jamais directement |
| `spec-reverse` | Reverse-engineering : rédige la spec la plus complète possible d'un fichier source existant, sans jamais toucher le code |
| `implementer` | Réalise une spec précise : tests d'abord depuis les `Scenario`, puis implémentation minimale |
| `validator` | Vérifie implémentation ↔ spec + batterie tests/clippy/fmt, remonte une synthèse si ce n'est pas bon |

## Commandes

Avant toute `Tasks` `[x]`, la batterie complète (définie par `validator`, reprise ici) :

```bash
cargo test                                            # default
cargo test --all-features
cargo test --no-default-features                      # seam racine : seule porte sans `rhai`
cargo test --no-default-features --features hbs       # graphe `hbs` seul (isolabilité #9)
cargo test --no-default-features --features k8s       # matrice de features
cargo test --no-default-features --features oci
cargo test --no-default-features --features s3
cargo test --no-default-features --features k8s,oci,s3
cargo test --no-default-features --features crypto              # verrou not(rhai) de key
cargo test --no-default-features --features rhai                # glue sans les features qu'elle câble
cargo test --no-default-features --features hbs,crypto         # helper crypto de Handlebars, sans `rhai`
cargo test --no-default-features --features rhai,shell         # les cinq verrous shell (signal, rc, extrait stderr)
cargo test --no-default-features --features rhai,fs            # branche gated `fs` des enregistrements de `new_bare` (`--each-feature` ne la compile pas)
cargo test --no-default-features --features rhai,password      # branche gated `password` des enregistrements de `new_bare`, idem
cargo clippy --all-targets -- -D warnings              # harnais default, code de test inclus (zéro warning toléré)
cargo clippy --no-default-features --features k8s --all-targets -- -D warnings
cargo clippy --no-default-features --features oci --all-targets -- -D warnings
cargo clippy --no-default-features --features s3 --all-targets -- -D warnings
cargo clippy --no-default-features --features k8s,oci,s3 --all-targets -- -D warnings
cargo clippy --no-default-features --features crypto --all-targets -- -D warnings
cargo clippy --no-default-features --features rhai --all-targets -- -D warnings
cargo clippy --no-default-features --features hbs,crypto --all-targets -- -D warnings
cargo clippy --no-default-features --features rhai,shell --all-targets -- -D warnings
cargo clippy --no-default-features --features rhai,fs --all-targets -- -D warnings
cargo clippy --no-default-features --features rhai,password --all-targets -- -D warnings
cargo clippy --all-features --all-targets -- -D warnings
cargo hack check --each-feature --no-dev-deps             # matrice chaque feature isolée
cargo hack clippy --each-feature --no-dev-deps -- -D warnings
cargo +nightly fmt -- --check                         # voir rustfmt.toml
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features   # lints rustdoc, porte unique
```

Le harnais clippy doit tourner sur **toutes** ces combinaisons : des lints `pedantic`
(`must_use_candidate` en premier) dépendent du graphe de features et peuvent ne se déclencher
que sur l'une d'elles (voir `tooling.sdd`).

Les deux commandes `cargo hack --each-feature` sont une **règle**, non une liste : elles
compilent et lintent chaque feature isolée (y compris `fs`, `shell`, `password`, `crypto`,
`http`, `hbs-scripting`…), là où la liste explicite ci-dessus ne nomme que des combinaisons à
verrou désigné — toute feature qu'aucun verrou nommé ne désigne n'est jouée que par elle.
Elles **ne remplacent pas** les combinaisons explicites qui portent un sens (`k8s,oci,s3`,
`--all-features`, `crypto`, `rhai`, `hbs,crypto`, `rhai,shell`, `rhai,fs`, `rhai,password`), qui restent en plus (voir `tooling.sdd`) :
une porte qui n'existe que parce qu'un verrou précis n'y tourne pas se nomme dans la liste, elle
ne se déduit pas de `--each-feature` qui ne fait que compiler.

Contraintes de features à préserver (voir racine `vyvil-core.sdd`) : `k8s`/`oci`/`s3`/`http`
impliquent `rhai` (leurs types cœur sont des API Rhai directes) ; `hbs-scripting` doit rester
isolable de `hbs` — `hbs` seul ne doit jamais réintroduire `handlebars/script_helper` (donc
`rhai`/`smartstring`) dans le graphe — voir <https://github.com/sebt3/vynil-core/issues/9>.

## Git

- Pas de `Co-Authored-By` dans les messages de commit.
- Spec, code et tests dans la même PR ; tâches `[x]` uniquement après vérifications vertes.
