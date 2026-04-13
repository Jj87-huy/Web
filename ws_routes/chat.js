const clients = new Set();

module.exports = function chatRouter(ws, req, wss) {

    clients.add(ws);

    console.log("Client chat connected");

    ws.on("message", (data) => {

        const message = data.toString();

        console.log("Chat:", message);

        // broadcast cho tất cả client
        for (const client of clients) {

            if (client.readyState === 1) {
                client.send(message);
            }

        }

    });

    ws.on("close", () => {
        clients.delete(ws);
        console.log("Client chat disconnected");
    });

};