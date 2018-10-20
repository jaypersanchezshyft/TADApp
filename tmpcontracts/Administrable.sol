pragma solidity ^0.4.19;

// Administrable Contract:
//
// The basic keyed permission access is done with a multiple signing & revocation certificiate mechanism.
// Built to be as light-weight as possible and still provide the flexibility required to manage full stack
// dapp integrations.
//
// Maximum capacity is 7 administrators. Threshold is at 2/7(max). Expectations are 2 out of 3.
// @note:@todo set up option for changing the threshold. would need to be very careful about promote/Revoked
//  steps.

// @note:@security:@safety: This function needs to be fully vetted and edge cases examined & documented.

contract Administrable {
    enum AdministratorAccess { Unknown, Promoted, Demoted }
    enum KeyPermissionAccess { Unknown, Signed, Revoked, Reset }
    
    uint8 constant maxAdministrators = 7;
    uint8 constant maxThreshold = 2;

    struct keyPermissions {
        mapping(address => KeyPermissionAccess) administratorSignatures;
        address[] administrators;

        uint8 permissionLevel;
    }

    address public owner;

    //administrators
    mapping (address => uint8) administrationRevocationVoting;
    mapping (address => AdministratorAccess) administrators;
    uint8 numAdministrators;

    mapping (bytes32 => keyPermissions) administratorMultisignPermissionedKeys;
    mapping (address => bytes32[]) administrator_to_multisignPermissionedKeysArray;

    // ** administrator management ** //

    //result:
    // 0 = not owner
    // 1 = already set first administrator
    // 2 = setup first administrator

    function setPrimaryAdministrator(address _newAdministratorAddress) public returns (uint8 result) {
        if (msg.sender == owner) {
            if (numAdministrators == 0)
            {
                administrators[_newAdministratorAddress] = AdministratorAccess.Promoted;
                numAdministrators++;

                //setup first administrator
                return 2;
            } else {

                //already set first administrator
                return 1;
            }
        } else {

            //not owner
            return 0;
        }
    }

    //result:
    // 0 = not administrator
    // 1 = administrator already set
    // 2 = new administrator set

    function setAdministrator(address _newAdministratorAddress) public returns (uint8 result) {
        if (isAdministrator(msg.sender)) {
            if (administrators[_newAdministratorAddress] != AdministratorAccess.Promoted) {
                administrators[_newAdministratorAddress] = AdministratorAccess.Promoted;
                numAdministrators++;

                //new administrator set
                return 2;
            } else {
                //administrator already set
                return 1;
            }
        } else {
            //not administrator
            return 0;
        }
    }

    //result:
    // 0 = not owner
    // 1 = administrator already inactive
    // 2 = added vote to revoke administrator
    // 3 = revoked administrator

    function revokeAdministrator(address _revokeAdministratorAddress) public returns (uint8 result) {
        if (isAdministrator(msg.sender)) {
            if (administrators[_revokeAdministratorAddress] == AdministratorAccess.Promoted) {
                bytes32 keyKeccak = keccak256("administrationRevocationVote");
                
                //@note: @here: admin consensus set at maxThreshold minimum
                uint16 multisignResult = adminApplyAndGetPermissionsForMultisignKey(keyKeccak);
                
                if (multisignResult >= maxThreshold) {
                    administrators[_revokeAdministratorAddress] = AdministratorAccess.Demoted;
                    numAdministrators--;
                    
                    //revoked administrator
                    return 3;
                } else {
                    //added vote to revoke administrator
                    return 2;
                }
            } else {
                //administrator already inactive
                return 1;
            }
        } else {
            //not administrator
            return 0;
        }
    }
    
    function checkForCleanupAfterRevocation(address _revokeAdministratorAddress) internal view returns (uint8 result) {
        if (isAdministrator(msg.sender)) {
            if  (administrators[_revokeAdministratorAddress] == AdministratorAccess.Demoted) {
                //check for permission level decreases across all permissioned keys
                for (uint i = 0; i < administrator_to_multisignPermissionedKeysArray[_revokeAdministratorAddress].length; i++) {
                    bytes32 keyKeccack = administrator_to_multisignPermissionedKeysArray[_revokeAdministratorAddress][i];
                    
                    //permission levels will decrease if it's below or at the maximum threshold level.
                    if (administratorMultisignPermissionedKeys[keyKeccack].permissionLevel <= maxThreshold) {
                        //cannot be cleaned up without disrupting permissioned keys
                        return 3;
                    } 
                }
                
                //can be cleaned up without disrupting permissioned keys
                return 2;
            } else {
                //administrator not revoked
                return 1;
            }
        } else {
            //not administrator
            return 0;
        }
    }
    
    function cleanupAfterRevocation(address _revokeAdministratorAddress) internal returns (uint8 result) {
        if (isAdministrator(msg.sender)) {
            if  (administrators[_revokeAdministratorAddress] == AdministratorAccess.Demoted) {
                for (uint i = 0; i < administrator_to_multisignPermissionedKeysArray[_revokeAdministratorAddress].length; i++) {
                    bytes32 keyKeccack = administrator_to_multisignPermissionedKeysArray[_revokeAdministratorAddress][i];
                    
                    administratorMultisignPermissionedKeys[keyKeccack].administratorSignatures[_revokeAdministratorAddress] = KeyPermissionAccess.Revoked;
                    administratorMultisignPermissionedKeys[keyKeccack].permissionLevel--;
                }
                
                //cleaned up
                return 2;
            } else {
                //cannot clean up
                return 1;
            }
        } else {
            //not administrator
            return 0;
        }
    }

    //result
    // 0 = not administrator
    // 1 to maxAdministrators = #confirmations

    function adminGetPermissionsForMultisignKey(bytes32 _keyKeccak) internal view returns (uint16 result) {
        if (isAdministrator(msg.sender)) {
            //(one to the maxAdministrators) #confirmations
            return administratorMultisignPermissionedKeys[_keyKeccak].permissionLevel;
        } else {
            //not administrator
            return 0;
        }
    }  

    //result
    // 0 = not administrator
    // 1 = signature not found
    // 2 = signature found
    // 3 = access revoked

    function adminGetSelfConfirmedFromMultisignKey(bytes32 _keyKeccak) internal view returns (uint16 result) {
        if (isAdministrator(msg.sender)) {
            if (administratorMultisignPermissionedKeys[_keyKeccak].administratorSignatures[msg.sender] == KeyPermissionAccess.Revoked) {
                //access revoked
                return 3;
            } else if (administratorMultisignPermissionedKeys[_keyKeccak].administratorSignatures[msg.sender] == KeyPermissionAccess.Signed) {
                //signature found
                return 2;
            } else {
                //signature not found
                return 1;
            }
        } else {
            //not administrator
            return 0;
        }
    }
    
    
    //result
    // 0 = not administrator
    // 1 to maxAdministrators = #confirmations

    function adminApplyAndGetPermissionsForMultisignKey(bytes32 _keyKeccak) internal returns (uint16 result) {
        if (isAdministrator(msg.sender)) {
            if (administratorMultisignPermissionedKeys[_keyKeccak].permissionLevel < maxAdministrators &&
                (administratorMultisignPermissionedKeys[_keyKeccak].administratorSignatures[msg.sender] == KeyPermissionAccess.Unknown ||
                administratorMultisignPermissionedKeys[_keyKeccak].administratorSignatures[msg.sender] == KeyPermissionAccess.Reset)) {
                // increase permission level of the key, apply signature.
                administratorMultisignPermissionedKeys[_keyKeccak].permissionLevel++;
                administratorMultisignPermissionedKeys[_keyKeccak].administratorSignatures[msg.sender] = KeyPermissionAccess.Signed;

                administratorMultisignPermissionedKeys[_keyKeccak].administrators.push(msg.sender);
                administrator_to_multisignPermissionedKeysArray[msg.sender].push(_keyKeccak);
            }
            
            //(one to the maxAdministrators) #confirmations
            return administratorMultisignPermissionedKeys[_keyKeccak].permissionLevel;
        } else {
            //not administrator
            return 0;
        }
    }
    
    //result
    // 0 = not administrator
    // 1 = already reset
    // 2 = reset correctly

    function adminResetPermissionsForMultisignKey(bytes32 _keyKeccak) internal returns (uint8 result) {
        if (isAdministrator(msg.sender)) {
            if (administratorMultisignPermissionedKeys[_keyKeccak].permissionLevel != 0) {
                //remove administrator references
                for (uint i = 0; i < administratorMultisignPermissionedKeys[_keyKeccak].administrators.length; i++) {
                    administratorMultisignPermissionedKeys[_keyKeccak].administratorSignatures[administratorMultisignPermissionedKeys[_keyKeccak].administrators[i]] = KeyPermissionAccess.Reset;
                }

                
                //delete the main holding array
                // delete administratorMultisignPermissionedKeys[_keyKeccak].administrators;
                administratorMultisignPermissionedKeys[_keyKeccak].administrators.length = 0;

                //and reset the permission level
                // delete administratorMultisignPermissionedKeys[_keyKeccak].permissionLevel;
                administratorMultisignPermissionedKeys[_keyKeccak].permissionLevel = 0;

                //reset correctly
                return 2;
            } else {
                //already reset
                return 1;
            }
        } else {
            //not administrator
            return 0;
        }
    }
    
    //returns:
    // false = not over threshold
    // true = is over threshold
    
    function isConfirmationsIsOverThreshold(uint8 _confirmationNumber) internal pure returns (bool result) {
        if (_confirmationNumber >= maxThreshold) {
            //is over threshold
            return true;
        } else {
            //not over threshold
            return false;
        }
    }

    //result: (internal because any derived contracts would probably want this.)
    // true = is administrator
    // false = either administrator unset or demoted
    
    function isAdministrator(address _administratorAddress) internal view returns (bool result) {
        if (administrators[_administratorAddress] == AdministratorAccess.Promoted) {
            //is administrator
            return true;
        } else {
            // either administrator unset or demoted
            return false;
        }
    }
}