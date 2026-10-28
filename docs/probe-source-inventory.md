# Original probe source inventory

Construction only. These are 6 admission and 28 shim probe program sources authored by builder-lineage child 0064 under parent 0003. No source was parsed, compiled, executed, or used to generate input. No oracle answers, expected outputs, observations, case records, or case hashes exist here. Licenses remain pending. The proposed metadata is partial intent and is not a native GENERATOR recipe or admission receipt.

Each `.cbl` and `.proposal.json` has its own raw-hash provenance sidecar; proposals declare intended input/output fields/layout and scenarios where relevant. No proposal is a completed recipe. The pinned corpus still needs concrete legal input records, distinct loop/verification recipes, independent reproduction, compiler observations, and all P2 GO checks.

| ID | Focus | Source raw SHA256 | Coverage |
|---|---|---|---|
| A01 | signed MOVE arithmetic and truncation | `256fca3b95ae6d0624a487dd7a0a8524ad78dc6336f2a392d47c0e186c0556f7` | proposed_unverified |
| A02 | ROUNDED positive/negative ties and adjacent values | `5c4b3508769e9b81c08392c84af9c08db3d58b67eef505ca8a68a18b8e2ad98e` | proposed_unverified |
| A03 | overflow with and without handler, destination before/after | `99827686654644bbcdaf0387ca84ff15680fe9bc1dcbd3ae062fb8c235b72a40` | proposed_unverified |
| A04 | present missing empty EOF input status | `cde93cf820ff7e16442adb32995d5a697acbedd1d48a70fa68e2957f61b35f29` | proposed_unverified |
| A05 | explicit two-digit integer year window with pivot 50; integer year pivot sides | `1bcaf2cecf6fff0f2d2f070d2d3c301c4ea79de9e7b8dc3fba9952cf0292f890` | proposed_unverified |
| A06 | ordinary versus trace source parity | `d36560226b63207133e42db6ef1c9b56754fcdfd590f3a492990ec36f4077eae` | proposed_unverified |
| S01 | positive rounded tie | `c1041ede4189695483cd468e8d3e28b46e685d0b1aaf9388a84cd411f9d8a245` | proposed_unverified |
| S02 | negative rounded tie | `f4fd2d4e6f80cf80076605892eb07e6fc8d6e0c75ca861c069b64a1ae25dc1bf` | proposed_unverified |
| S03 | positive below tie | `8d5f765135ddb830bcd7ed96caf119e7029e520e5cd76a1a9b29dce2c1915015` | proposed_unverified |
| S04 | positive above tie | `fd9e5c08f036f292f8e080c8858d504c244bf311fdb0b704c5dd985799b2ecce` | proposed_unverified |
| S05 | negative below magnitude tie | `b3393e16b0018b4384daf7414b9a6324214ba9edd0f9e7385aeabdf0df93acc1` | proposed_unverified |
| S06 | negative above magnitude tie | `c0da5c873af7f24c042b7baa5cc376fb3457ce1b8b2f358bd7aad2c0d0ff4a3d` | proposed_unverified |
| S07 | tiny discarded positive fraction | `740970c41e1f815ffb7a34f6ef594b3bd06f6c40c3e0e04c6ca870d4e1f305c4` | proposed_unverified |
| S08 | tiny discarded negative fraction | `e9f5ae50e0fc357d52ee59a812f8d6b97946a14368191ba5ced6541d5c907ddd` | proposed_unverified |
| S09 | positive truncation without ROUNDED | `f42182b34fee764897c3ef5b3a41d6fd4d3daae7f5253ade9b9a4ae8237fad6d` | proposed_unverified |
| S10 | negative truncation without ROUNDED | `fef7c3ce07540f3ce62e2431078076000667073d01465e9a8ca806cf9eaafd88` | proposed_unverified |
| S11 | negative zero through MOVE | `41a67e01c511a57e4789c8265893c4cbbf067395558a5f39dd725d160165d2a9` | proposed_unverified |
| S12 | negative zero through arithmetic | `24f30b0166187ee8ba6f7abcbd46ace634b6a7fa2b32ef38b0d296ad59d9a16b` | proposed_unverified |
| S13 | leading separate sign width and position | `d78323b636645caafb2ba93caf6605bf23f3991e43b8558e6c134d601074ce16` | proposed_unverified |
| S14 | trailing separate sign pending: only leading proxy is inside subset | `01c05160f9bb6bb69e3e6973b1def738a8439b707d484b94119b4ea3705b5f0c` | partial_pending_out_of_subset_measurement |
| S15 | internal COMP-3 byte size pending: only value movement is observable | `8b3667b5ef21084b37665dddf1c0e48f3251c2a46b837342fe1c8c2fe3eb79cf` | partial_pending_out_of_subset_measurement |
| S16 | internal packed truncation to display | `1089553d46b9372e87c29ec7ad54b080a2c3ed40e17eedc4992938cbcddbed0e` | proposed_unverified |
| S17 | overflow without handler | `5890447919cc76e5c7d78c8427431a1ccd88b06a3c8be514aaa786bf891dd39c` | proposed_unverified |
| S18 | overflow with SIZE ERROR handler | `d326d4a5f67dc87a4dd68fd680bfe09c2c02f67b38acc121753e76f896657e6c` | proposed_unverified |
| S19 | destination sentinel on SIZE ERROR | `c2f7100f7182c81c1811554d81eaac4976f668e7f2b4f4c3671fb67f130eebf9` | proposed_unverified |
| S20 | divide by zero handled and unhandled | `e469bcff3132f5f68d916cd452da358c01ddbc0bfbdce688269d70891ea5b4d0` | proposed_unverified |
| S21 | multi-operator COMPUTE intermediate order | `1bdd2f14bb9a9cca1b5a45c7da34a50b32f77cfb50373654556f2dbd3cb85a81` | proposed_unverified |
| S22 | missing input status | `570b4432c6669fd45be102658e5d95ce5718031f711765bb6ee361e93652d772` | proposed_unverified |
| S23 | empty input first and subsequent EOF | `ca2d7571f38ef2929d375c7a6452d8545030cb62852e8474c826b0f96bce5a76` | proposed_unverified |
| S24 | explicit two-digit integer year window with pivot 50; year pivot minus one and pivot | `6b4731bbf3fffbfb1d71d8fe498531783ed615a376856eef1c51ef9960fbd0b8` | proposed_unverified |
| S25 | explicit two-digit integer year window with pivot 50; year pivot plus one | `802fa480de3e8a02dbe24e1783a2993bad8f98eec22ad1127acf430d9d805af6` | proposed_unverified |
| S26 | signed to unsigned MOVE | `b39bf01c11a52cc66eec056104dd4409d3034272fd76456ad4faf36e6d58c432` | proposed_unverified |
| S27 | alphanumeric padding and truncation | `46158611b3c867667d9a8a4921d1a5d6030f1d927e700568b313e1bca8ce87b3` | proposed_unverified |
| S28 | ordered input records and presence | `dada035cab323059c7fac1edfe233e572f33002009ec926132165be811ee7ebb` | proposed_unverified |

## Explicit limitations

- S14: `SIGN TRAILING SEPARATE` is outside SUBSET v1. The source uses supported leading separate sign only. Trailing sign width/position remains unmeasured; this probe is incomplete.
- S15: internal COMP-3 byte-size observation needs LENGTH or another explicit compiler-observable size construct outside SUBSET v1. The source emits moved values only. Odd/even internal storage sizes remain unmeasured; this probe is incomplete.
- A04, S22, S23, S28: OPEN success is checked before READ or CLOSE. Status is emitted on open, read/EOF, and close; a second READ occurs only after a successful first READ. Their missing, empty, ordered, and present scenarios remain proposed only. S28 requires distinct ordered records and a distinct missing/empty case when later authored.
- S13 writes an external signed output field, guarded by successful OPEN, to make physical sign position and width observable later; no output has been generated. S14 retains only a leading-sign input proxy, with no actual input record bytes. A05/S24/S25 source-declare a two-digit pivot of 50 and mapping below pivot to 2000+YY, otherwise 1900+YY; this is a proposed algorithm, not a compiler finding or a built-in year-window claim.
- A06 has one unchanged source for later ordinary/trace builds and repeated observations; no build or parity check occurred.
- Statements and metadata have not been validated by a parser or GnuCOBOL. Compiler acceptance, line-sequential physical framing, signed-zero retention, overflow behavior, divide-by-zero behavior, and all claimed focuses remain open.

Corrective source revision: S11/S12/S16/S21 now explicitly declare DEC-OUT PIC S9(3)V9(2) SIGN LEADING SEPARATE, the intended signed quantization receiver. Parent0003 revised these child0064 sources and metadata after XHigh found unresolved references; raw sidecars retain original author/session and prior edition hashes. No source was executed or parsed.
