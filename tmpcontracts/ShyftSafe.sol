pragma solidity ^0.4.19;
import "./Interfaces/IShyftBridgeUtilsProver.sol";

// Shyft Safe is the contract & interface definition to add "Safe-able" asset classes to a user's portfolio.
// This is a data management layer that collates enough data on-chain for the Bridge to prove transferability.
// All transfers and justification for withdrawal can be proven on-chain.
//
// The general condition is that there is a list of unproven proofs, including those that the bridge collates via
// observation of other blockchains. All cross-blockchain requests are queued in the user's "safe keeping" structure
// and the bridge has the responsibility to process them and approve. All proofs can be proven on the Shyft blockchain's
// evm architecture.

// the general order of things is that when a block is confirmed by consensus, the bridge will forward a merkle-trie
// proof block to the ring which is composed of transactions occurring on other blockchains that pertains to Shyft.
// these are cleared transactions, currently waiting in Shyft escrow systems.

// these transactions are processed in every block, with block times set to enable this behaviour potentially filling
// up empty space within a block with these transactions at a rate dependant on the user (so users could still "rush"
// a Shyft Safe synchronization block.

// maintenance of the trust channels should be equivalent

//@note:@todo: finish definition

contract ShyftSafe {
    event EVT_heldSafeBalanceForType(uint256 amount, uint32 bip32X_type, uint256 safeExpiryTime, uint256 holdIndex);
    event EVT_freedSafeHold(uint256 holdIndex, uint256 numRemainingHolds, HoldStatus holdStatus, uint256 freedAmount, uint256 freedBip32X_type, uint256 currentBlockTime, uint256 safeExpiryTime);
    event EVT_safeHoldStillTimelocked(uint256 holdIndex, uint256 numRemainingHolds, uint256 currentBlockTime, uint256 safeExpiryTime);

    enum ProofStatus { Unknown, Dirty, Clean }
    enum HoldStatus { Unknown, Holding, NoneHeld }

    struct safeProofMap {
        //hash of RLP
        bytes32 proofHash;

        //RLP of proof
        bytes proof;

        bytes publicMetadata;
        bytes encryptedMetadata;

        uint256 amount;
        uint32 bip32X_type;

        bool proven;
    }

    struct safeKeyMap {
        //key name, key class, key field. RLP encoded.
        bytes publicMetaData;

    }

    struct safeHold {
        bool active;

        uint256 amount;
        uint32 bip32X_type;

        uint256 safeExpiryTime;
    }

    struct safeKeep {
        //hash of the public key value pair within the Safe engine, for incoming addresses in the proofs.
        mapping(bytes32 => safeKeyMap) keyStorageMap;

        //array of all proofs.
        safeProofMap[] allProofs;

        uint32 indexOfFirstDirtyProof;
        uint32 numDirtyProofs;

        //@note:@here:@todo:@next:@wallet:
        //this hold array will grow and be managed by the wallet in terms of releasing funds back into the
        //main shyft safe pool.
        //speaking of transiting, the general strategy should be to assign held tokens into transit buckets
        //on a hold bucket->transit bucket basis. otherwise other sorting and compilation will be needed.
        safeHold[] holdArray;

        //using a doubly linked list for this, in order to access the previous and next indexes in the linked list.
        mapping(uint32 => uint32) holdNextLinkMapping;
        mapping(uint32 => uint32) holdPrevLinkMapping;

        //mapping for checks of whether the trust anchor previously existing for this identifiedAddress.
//        mapping(uint32 => bool) allTrustAnchorIndexExistsMapping;

        //@note: I'm using underscores because I want to have easily readability when the camel case variable names get
        // this long.

        uint16 currentHoldLinkedList_length;
        uint32 currentHoldLinkedList_zeldaIndex;
        uint32 currentHoldLinkedList_finalIndex;



        mapping(uint32 => uint256) holdValuationMap;

        uint256 nextHoldExpiry;
//        uint32 holdArrayNumHolds;

        HoldStatus holdStatus;
    }

    mapping(address => safeKeep) safeKeeping;

    //@note:@here:@todo: this is erc20/223 stuff
    // system should be backwards compatible, basic table:
    //
    // (all bip32 token types follow)
    // 0 = Bitcoin
    // ...
    // ShyftTokenType = SHYFT
    // RMTTokenType = RMT
    // BUAGTokenType = BUAG
    // ...

    mapping(address => mapping(uint32 => uint256)) safeBalances;

    ProofStatus proofStatus;

    uint16 maxBridgeProcessingLimit;

    uint32 ShyftTokenType = 777;

    //@note:@deploy:
    //make sure to set this to use the shyft bridge and ring on whatever platform deployed to. might need to
    //create multiple versions of this file and deploy w/ a script.

    //this is the address of the Shyft bridge on this blockchain. this must be hard-coded.
    address bridgeAddress = address(0);

    //returns
    // true = is bridge
    // false = not bridge
    function isBridge(address _addressToCheck) internal returns (bool result) {
        return (bridgeAddress == _addressToCheck);
    }

    function getShyftTokenType() public view returns (uint32 result) {
        return ShyftTokenType;
    }

    function getSafeBalance(address _identifiedAddress) public view returns (uint256 balance)  {
        return safeBalances[_identifiedAddress][ShyftTokenType];
    }

    function getSafeBalance(address _identifiedAddress, uint32 bip32X_type) public view returns (uint256 balance)  {
        return safeBalances[_identifiedAddress][bip32X_type];
    }

    //@note:@here: the following two functions utilize doubly-linked lists in order to avoid needing to reorder an array.

    //@note:@todo:@next: need to write complete tests for these two functions too see how the doubly-linked list responds
    // in all cases (1, 2. 3 entries, what happens when first, middle, or last entry are removed from holds.)

    //returns:
    // n = holdIndex

    function holdSafeBalanceForType(uint256 _amount, uint32 _bip32X_type, uint256 _safeExpiryTime) public returns (uint256 holdIndex) {
        //@note: this works because functional inheritance overriding works in solidity. thus this will call the
        // function of the contract that overrides overload_doHoldSafe after inheriting ShyftSafe.
        uint8 canHoldSafeResult;
        uint256 remainingBalance;
        (canHoldSafeResult, remainingBalance) = child_overload_doHoldSafe(_amount, _bip32X_type);

        //@note:@here:@todo: checks for payments pending, allowances, and the like.
        //if (remainingBalance > )

        //@note: in this context, the inheriting contract overriding function is going to return a 1 for success,
        // and zero for failure.
        if (canHoldSafeResult == 1) {
            safeHold memory newHold;
            newHold.amount = _amount;
            newHold.bip32X_type = _bip32X_type;
            newHold.safeExpiryTime = _safeExpiryTime;
            newHold.active = true;

            safeKeep storage keep = safeKeeping[tx.origin];
            keep.holdValuationMap[_bip32X_type] += _amount;

            uint32 holdArrayLength = uint32(keep.holdArray.length + 1);
            keep.holdArray.length = holdArrayLength;

            keep.holdArray[holdArrayLength - 1] = newHold;

            //set up the linked list to allow for array accessibility without needing to rearrange or delete old
            // members of the array.
            if (keep.holdStatus != HoldStatus.Holding) {
                keep.holdStatus = HoldStatus.Holding;

                //set up the zelda address of the doubly-linked list (the first entry into the doubly-linked list).
                keep.currentHoldLinkedList_zeldaIndex = holdArrayLength - 1;
                //and set the final index to this as well for further additions.
                keep.currentHoldLinkedList_finalIndex = holdArrayLength - 1;

                keep.currentHoldLinkedList_length = 1;
            } else {
                //update the prev index of this index in the doubly-linked list to point to this (previously final) index.
                keep.holdPrevLinkMapping[holdArrayLength - 1] = keep.currentHoldLinkedList_finalIndex;
                //update the final index in the doubly-linked list to point to this index.
                keep.holdNextLinkMapping[keep.currentHoldLinkedList_finalIndex] = holdArrayLength - 1;
                //and set the final index to this as well for further additions.
                keep.currentHoldLinkedList_finalIndex = holdArrayLength - 1;

                keep.currentHoldLinkedList_length++;
            }

            EVT_heldSafeBalanceForType(_amount, _bip32X_type, _safeExpiryTime, keep.holdArray.length);

            //hold index
            return keep.holdArray.length;
        } else {
            //must revert here, since values were modified downstream in the inherited contracts.
            revert();
        }
    }

    //returns:
    // 0 = keep's holds array less than holdIndex
    // 1 = hold expiry time higher than current block timestamp
    // 2 = could not free hold @note: reverts, since transactional event has occurred
    // 3 = freed hold properly

    function freeSafeHold(uint32 holdIndex) public returns (uint8 result) {
        safeKeep storage keep = safeKeeping[tx.origin];

        //make sure that the holdIndex is within the range of 0->(holdArray.length - 1), and that this hold is active.
        if (keep.holdArray.length > holdIndex && keep.holdArray[holdIndex].active == true) {
            safeHold storage hold = keep.holdArray[holdIndex];

            if (hold.safeExpiryTime <= block.timestamp) {
                uint8 freeSafeResult = child_overload_doFreeSafe(hold.amount, hold.bip32X_type);

                if (freeSafeResult == 1) {
                    //in both subsequent cases, the total size of the doubly-linked list decreased by one.
                    keep.currentHoldLinkedList_length--;

                    //and similarly, in both cases this hold is marked inactive.
                    keep.holdArray[holdIndex].active = false;

                    //check if this hold is the zelda (first) index within the doubly-linked list.
                    if (holdIndex == keep.currentHoldLinkedList_zeldaIndex) {
                        //check if this hold is also the final index within the doubly-linked list.
                        if (holdIndex == keep.currentHoldLinkedList_finalIndex) {
                            //in this case, no remapping is necessary.
                        } else {
                           //otherwise, set the zelda index to be the next index in the doubly-linked list.
                            keep.currentHoldLinkedList_zeldaIndex = keep.holdNextLinkMapping[holdIndex];
                        }
                    } else {
                        //check if this hold is the final index within the doubly-linked list.
                        if (holdIndex == keep.currentHoldLinkedList_finalIndex) {
                            //if so, set final link in the doubly-linked list to be the the previous link of this index.
                            keep.currentHoldLinkedList_finalIndex = keep.holdPrevLinkMapping[holdIndex];
                        } else {
                            //if not, this link is in between the zelda and final index within the doubly-linked list.
                            // in this case, set the previous link to have its next link to be the next link of the
                            // current hold. the final index of this doubly-linked list does not change.

                            uint32 prevLink = keep.holdPrevLinkMapping[holdIndex];
                            uint32 nextLink = keep.holdNextLinkMapping[holdIndex];

                            keep.holdPrevLinkMapping[nextLink] = prevLink;
                            keep.holdNextLinkMapping[prevLink] = nextLink;
                        }
                    }

                    //if there's zero entries left within the doubly-linked list, the keep status is set to NoneHeld.
                    if (keep.currentHoldLinkedList_length == 0) {
                        keep.holdStatus = HoldStatus.NoneHeld;
                    }


                    EVT_freedSafeHold(holdIndex, keep.currentHoldLinkedList_length, keep.holdStatus, hold.amount, hold.bip32X_type, block.timestamp, hold.safeExpiryTime);

                    //freed hold properly
                    return 3;
                } else {
                    revert();

                    //could not free hold @note: reverts, since transactional event has occurred
                    return 2;
                }

            } else {
                EVT_safeHoldStillTimelocked(holdIndex, keep.currentHoldLinkedList_length, block.timestamp, hold.safeExpiryTime);

                //hold expiry time higher than current block timestamp
                return 1;
            }
        } else {
            //keep's holds array less than holdIndex
            return 0;
        }
    }

    //@note:@here: the following two functions are stub functions for contracts inheriting this contract (shyft kyc
    // contract for example.

    //returns:
    // 0 = failure
    // 1 = success
    function child_overload_doHoldSafe(uint256 amount, uint32 bip32X_type) internal returns (uint8 result, uint256 remainingBalance) {
        return (0, 0);
    }
    //returns:
    // 0 = could not free
    // 1 = freed
    function child_overload_doFreeSafe(uint256 amount, uint32 bip32X_type) internal returns (uint8 result) {
        return 0;
    }


    //returns:
    // 0 = not bridge nor proper owner
    // 1 = proof set

    function addProof(address _identifiedAddress, bytes32 _proofHash, bytes _proof, bytes _publicMetadata, bytes _encryptedMetadata, uint256 _amount, uint32 _bip32X_type) public returns (uint16 result) {
        if (isBridge(msg.sender) || msg.sender == _identifiedAddress) {
            uint32 numProofs = uint32(safeKeeping[_identifiedAddress].allProofs.length + 1);

            safeKeeping[_identifiedAddress].allProofs.length = numProofs;
            safeProofMap storage proofMap = safeKeeping[_identifiedAddress].allProofs[numProofs - 1];

            proofMap.proofHash = _proofHash;
            proofMap.proof = _proof;
            proofMap.publicMetadata = _publicMetadata;
            proofMap.encryptedMetadata = _encryptedMetadata;
            proofMap.amount = _amount;
            proofMap.bip32X_type = _bip32X_type;

            if (proofStatus == ProofStatus.Clean) {
                proofStatus = ProofStatus.Dirty;
                safeKeeping[_identifiedAddress].indexOfFirstDirtyProof = numProofs - 1;
                safeKeeping[_identifiedAddress].numDirtyProofs = 1;
            } else {
                safeKeeping[_identifiedAddress].numDirtyProofs++;
            }

            return 1;
        } else {
            //not bridge nor proper owner
            return 0;
        }
    }

    //returns:
    // 0 = not bridge
    // 1 = proofs not dirty
    // 2 = some proven, needs to process further
    // 3 = all proofs are now proven
    function updateSafe(address _identifiedAddress) public returns (uint16 result) {
        if (isBridge(msg.sender)) {
            if (proofStatus != ProofStatus.Clean) {
                IShyftBridgeUtilsProver prover = IShyftBridgeUtilsProver(bridgeAddress);

                safeKeep storage keep = safeKeeping[_identifiedAddress];

                bool needsToProcessFurther;

                uint32 numToProcess = keep.numDirtyProofs;
                if (numToProcess > maxBridgeProcessingLimit) {
                    numToProcess = maxBridgeProcessingLimit;
                    needsToProcessFurther = true;
                }

                for (uint32 i = keep.indexOfFirstDirtyProof; i < numToProcess; i++) {
                    keep.allProofs[i].proven = prover.prove(keep.allProofs[i].proof);
                }

                keep.indexOfFirstDirtyProof += numToProcess;

                if (!needsToProcessFurther) {
                    proofStatus = ProofStatus.Clean;

                    //@note: @here: this should be here except for an issue in the ganache-cli vm which
                    //prevents resets to zero due to some sort of gas estimation issue.
                    //keep.numDirtyProofs = 0;

                    //all proofs are now proven
                    return 3;
                } else {
                    //some proven, needs to process further
                    return 2;
                }
            } else {
                //proofs not dirty
                return 1;
            }
        } else {
            //not bridge
            return 0;
        }
    }

    //returns
    // true = proof successful
    // false = proof unsuccessful

    function safeProofProver(bytes proof) public returns (bool result) {
        IShyftBridgeUtilsProver prover = IShyftBridgeUtilsProver(bridgeAddress);

        return prover.prove(proof);
    }
}