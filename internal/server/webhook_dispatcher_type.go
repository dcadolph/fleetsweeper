package server

import "github.com/dcadolph/fleetsweeper/internal/webhooks"

// webhookDispatcher is a type alias kept in its own file so the server's
// imports list does not have to grow whenever the dispatcher's public
// interface changes.
type webhookDispatcher = webhooks.Dispatcher
