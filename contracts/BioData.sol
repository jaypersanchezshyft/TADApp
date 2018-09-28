pragma solidity ^0.4.18;

contract BioData {
    struct BioDataObj {
        uint id;
        address contractOwner;
        string firstName;
        string middleName;
        string lastName;
    }

    mapping(uint => BioDataObj) public biodatalist;
    uint recordCounter;
    
    constructor() public {
        //BioDataObj.contractOwner = msg.sender;
    }

    event LogSetBioData(uint indexed _id, address indexed _contractOwner, string _firstName, string _middleName, string _lastName);

    function setBioData(string _firstName, string _middleName, string _lastName) public {
        /*contractOwner = msg.sender;
        firstName = _firstName;
        lastName = _lastName;
        middleName = _middleName;*/
        //increment counter
        recordCounter++;
        //store BioData
        biodatalist[recordCounter] = BioDataObj(recordCounter,msg.sender,_firstName, _middleName, _lastName);
        //triger set event
        emit LogSetBioData(recordCounter,msg.sender, _firstName, _middleName, _lastName);
    }

    //fetch number of bio data items
    function getNumberOfBioDataItems() public view returns (uint) {
        return recordCounter;
    }

    //fetch and return all bio data that is saved
    function getBioData() public view returns (uint[]) {
        //prepare output array
        uint[] memory bioDataIds = new uint[](recordCounter);
        uint numberOfSavedBioData = 0;
        //itirate over biodatalist
        for(uint i = 1; i <= recordCounter; i++) {
            //show bio data item
            bioDataIds[numberOfSavedBioData] = biodatalist[i].id;
            numberOfSavedBioData++;
        }
        //copy bioDataIds array just get ids pertaining to contractOwner
        uint[] memory owneddata = new uint[](numberOfSavedBioData);
        for(uint j = 0; j < numberOfSavedBioData; j++) {
            owneddata[j] = bioDataIds[j];
        }

        return owneddata;
    }

    /*function getBioData(uint _id) public view returns(uint, address, string, string, string) {
            require(recordCounter > 0);
            //check that _id exist in the biodatalist
            require(_id > 0 && _id <= recordCounter);
            //retrieve bio data from mapping
            BioDataObj storage bioDataItem = biodatalist[_id]; 
            require(msg.sender != bioDataItem.contractOwner);
            event LogSetBioData(bioDataItem.id, bioDataItem.contractOwner, bioDataItem.firstName, bioDataItem.middleName, bioDataItem.lastName);
            return(_id, bioDataItem.contractOwner, bioDataItem.firstName, bioDataItem.middleName, bioDataItem.lastName);
    }*/

}