package bank

type Account struct {
	Name   string
	Number string
	Amount Amount
}

type Amount int

type Auth interface {
	OAuthSnap()
}

type Bank interface {
	Inquiry(accNum string) Account
	// TransferIntraBank()
	// TransferInterBank()
	// VirtualAccount()
}
