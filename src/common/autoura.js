import {didTools} from "@/common/did";

export const autoura = {

    async callAutouraService(my_did) {
        try {

            this.response = {};

            // Sign the payload as a JWT
            const signedJWT = await didTools.createJWT(my_did.privateKeys[0], my_did.uri, my_did.uri);

            // Autoura.me service URL
            const serviceUrl = didTools.get_test_did_service_url('preferences');

            // Call Autoura.me service
            const response = await fetch(serviceUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${signedJWT}`,
                },
            });

            // Display Autoura.me service response
            return await response.json();

        } catch (error) {
            console.error('Error signing and sending JWT:', error);
        }

    }

}