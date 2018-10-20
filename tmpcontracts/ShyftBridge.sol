pragma solidity ^0.4.19;

import "./Interfaces/IShyftBridgeUtilsProver.sol";

import "./Administrable.sol";

contract ShyftBridge is Administrable {

    address shyftSafeAddress = address(0);

    function ShyftBridge() public {
        owner = msg.sender;
    }

    //returns:
    // 0 = not an administrator
    // 1 = only one administrator has permissioned change
    // 2 = shyft safe set

    function setShyftSafeAddress(address _shyftSafeAddress) public returns (uint8 result) {
        require(_shyftSafeAddress != address(0));

        if (isAdministrator(msg.sender)) {
            bytes32 keyKeccak = keccak256("shyftSafeAddress", _shyftSafeAddress);

            uint16 numPermissions = adminGetPermissionsForMultisignKey(keyKeccak);

            bool permittedToModify;

            if (numPermissions >= maxThreshold) {
                permittedToModify = true;
            } else {
                uint16 numConfirmedPermissions = adminApplyAndGetPermissionsForMultisignKey(keyKeccak);

                if (numConfirmedPermissions >= maxThreshold) {
                    permittedToModify = true;
                }
            }

            if (permittedToModify == true) {
                shyftSafeAddress = _shyftSafeAddress;

                adminResetPermissionsForMultisignKey(keyKeccak);

                // shyft safe set
                return 2;

            } else {
                // not enough administrators have permissioned change
                return 1;
            }
        } else {
            // not an administrator
            return 0;
        }
    }

    //@note: a (wallet) user calls this function to begin the process of "transiting" (moving) their assets across
    // blockchains.
    //
    // the user needs to have assets currently within their Safe hold(s). as long as the asset is with their Safe hold(s)
    // it is guaranteed to be a balance they can transit. in order to induce a proper locking mechanism, the asset has a
    // minimum block confirmation of 6 blocks

    //returns:
    //

    function transitAsset(uint32 _bip32X_type, uint256 _value, bytes32 _toChainId) public returns (uint8 result) {

    }

    function prove(bytes proof) public returns (bool proven) {
        return true;
    }
}
