package drivers

type Driver interface {
	CreateTable() error
}
