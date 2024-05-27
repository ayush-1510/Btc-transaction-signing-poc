// Import fetch from node-fetch
import fetch from 'node-fetch';
import PromptSync from 'prompt-sync';
const prompt = PromptSync();

function Transaction(){
    var txnType = prompt("Type of Txn: ");
    switch(txnType){
        case '1':
            var toAddr = prompt('To addr: ');
            var ownerAddr = prompt('owner Addr: ');
            var visible = prompt('Visible: ');
            var amount = prompt('Amount: ');
            // Data for the POST request
            const postData = {
                to_address: toAddr,//"41e9d79cc47518930bc322d9bf7cddd260a0260a8d",
                owner_address: ownerAddr,//"41D1E7A6BC354106CB410E65FF8B181C600FF14292",
                visible: visible,//false
                amount: parseInt(amount),
                
            };

            // Making the POST request using fetch
            fetch('https://api.shasta.trongrid.io/wallet/createtransaction', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(postData)
            })
            .then(response => response.json()) // Parsing the JSON response
            .then(data => console.log(JSON.stringify(data, null, 2))) // Handling the success
            .catch(error => console.error('Error:', error)); // Handling errors
                }

}
Transaction();