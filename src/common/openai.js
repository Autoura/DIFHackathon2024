export const openai = {

    create_prompt(preferences, specials) {

        let prompt = 'You are the restaurant manager of a restaurant called "The British Pantry" within a hotel called "The Grand Britannia". You are writing a message to a guest asking if they would like to join you for dinner in your restaurant that is conveniently located within the hotel building. Your restaurant is casual so you can address the guest casually. Your name is Nick. It is currently lunch time and you are asking about this evening\'s dinner';

        prompt += '\n\nYour specials for tonight include:';
        prompt += '\n' + specials;
        prompt += '\n\nAn a la carte menu is also available.';

        prompt += '\nGuest name';
        prompt += '\nFirst name:' + preferences.service.contact.name_f;
        prompt += '\nSurname name:' + preferences.service.contact.name_s;

        prompt += '\n\nDescribe specials that match the guests requirements. DO NOT suggest specials that are not suitable. DO mention that you have considered their preferences. DO not mention their preferences except within the context of a special dish suggestion';

        // Food
        let eat_personalisation = "";
        let personalisation = "";
        let eatEverything = true;

        if (!preferences.discovery.food.meat) {
            personalisation += `\n${preferences.service.contact.name_f} does not eat meat so do not suggest any meat or poultry dishes.`;
            eatEverything = false;
        } else {
            eat_personalisation += `\n${preferences.service.contact.name_f} does eat meat and poultry.`;
        }

        if (!preferences.discovery.food.fish) {
            personalisation += `\n${preferences.service.contact.name_f} does not eat fish so do not suggest any fish or seafood dishes.`;
            eatEverything = false;
        } else {
            eat_personalisation += `\n${preferences.service.contact.name_f} does eat fish.`;
        }

        if (!preferences.discovery.food.insects) {
            personalisation += `\n${preferences.service.contact.name_f} does not eat insects so do not suggest dishes that include insects.`;
            eatEverything = false;
        } else {
            eat_personalisation += `\n${preferences.service.contact.name_f} does eat insects.`;
        }

        if (!preferences.discovery.food.dairy) {
            personalisation += `\n${preferences.service.contact.name_f} does not eat dairy so do not suggest dishes containing milk or cheese.`;
            eatEverything = false;
        } else {
            eat_personalisation += `\n${preferences.service.contact.name_f} does eat dairy.`;
        }

        if (!preferences.discovery.food.gluten) {
            personalisation += `\n${preferences.service.contact.name_f} does not eat gluten so do not suggest dishes containing gluten.`;
            eatEverything = false;
        } else {
            eat_personalisation += `\n${preferences.service.contact.name_f} does eat gluten.`;
        }

        if (!preferences.discovery.food.alcohol) {
            personalisation += `\n${preferences.service.contact.name_f} does not drink alcohol so do not discuss cocktails or other alcoholic drinks.`;
            eatEverything = false;
        } else {
            eat_personalisation += `\n${preferences.service.contact.name_f} does drink alcohol.`;
        }

        if (!preferences.discovery.food.eggs) {
            personalisation += `\n${preferences.service.contact.name_f} does not eat egg so do not suggest dishes containing egg.`;
            eatEverything = false;
        } else {
            eat_personalisation += `\n${preferences.service.contact.name_f} does eat egg.`;
        }

        if (!preferences.discovery.food.honey) {
            personalisation += `\n${preferences.service.contact.name_f} does not eat honey so do not suggest dishes containing honey.`;
            eatEverything = false;
        } else {
            eat_personalisation += `\n${preferences.service.contact.name_f} does eat honey.`;
        }

        if (eatEverything) {
            personalisation += `\n${preferences.service.contact.name_f} does eat everything including meat, fish, gluten, insects, egg, honey, and dairy, and they drink alcohol.`;
        } else {
            // Positively say what they do eat (won't be everything)
            personalisation += eat_personalisation;
        }

        // Adding to the JavaScript prompt
        prompt += '\n\nDescribe specials that match the guests requirements. DO NOT suggest specials that are not suitable. DO mention that you have considered their preferences.';
        prompt += personalisation;

        // More advanced applications we could consider budget, accessibility (wheelchair) etc

        return prompt;
    },

    async ask_openai(prompt) {
        let api_key = process.env.VUE_APP_OPENAI;
        api_key = api_key.replace(/^['"]|['"]$/g, '');

        try {
            const response = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${api_key}`
                },
                body: JSON.stringify({
                    model: "gpt-4o",
                    max_tokens: 4096,
                    messages: [
                        {role: "system", content: "You are an expert AI assistant that provides accurate and concise information"},
                        {role: "user", content: prompt}
                    ]
                })
            });

            const data = await response.json();

            if (response.ok) {
                return data.choices[0].message.content;
            } else {
                console.error("Error from OpenAI:", data);
                throw new Error(data.error.message || "Failed to get a response from OpenAI");
            }
        } catch (error) {
            console.error("Error:", error);
            throw error;
        }
    }


}