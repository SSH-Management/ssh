package ssh

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"path"

	"github.com/SSH-Management/utils"
	"golang.org/x/crypto/ssh"
)

type (
	Interface interface {
		Write() error
	}

	SSH struct {
		userId     int
		userGroup  int
		homeFolder string
		logger     *log.Logger

		private ed25519.PrivateKey
		public  ed25519.PublicKey
	}
)

const PrivateKeyFileName = "id_ed25519"
const PublicKeyFileName = "id_ed25519.pub"

var (
	ErrCannotCreateSSHFolder  = errors.New("Cannot create .ssh folder in home folder")
	ErrCannotChangePermission = errors.New("Cannot change permission for the file or directory")
)

func New(userId, userGroup int, homeFolder string) (SSH, error) {
	public, private, err := ed25519.GenerateKey(nil)

	if err != nil {
		return SSH{}, err
	}

	return SSH{
		userId:     userId,
		userGroup:  userGroup,
		homeFolder: homeFolder,
		public:     public,
		private:    private,
	}, nil
}

func (s SSH) Write() error {
	sshDir, err := s.createSSHFolderInHome()

	if err != nil {
		return err
	}

	if err := s.encodePrivateKey(sshDir); err != nil {
		return err
	}

	if err := s.encodePublicKey(sshDir); err != nil {
		return err
	}

	return nil
}

func (s SSH) createSSHFolderInHome() (string, error) {
	p, err := utils.CreateDirectory(path.Join(s.homeFolder, ".ssh"), 0o700)

	if err != nil {
		return "", ErrCannotCreateSSHFolder
	}

	if err := os.Chown(p, s.userId, s.userGroup); err != nil {
		return "", ErrCannotChangePermission
	}

	return p, nil
}

func (s SSH) encodePrivateKey(sshDir string) error {
	privateKeyPath := path.Join(sshDir, PrivateKeyFileName)
	b, err := x509.MarshalPKCS8PrivateKey(s.private)

	if err != nil {
		return err
	}

	block := pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: b,
	}

	return os.WriteFile(privateKeyPath, pem.EncodeToMemory(&block), 0o600)
}

func (s SSH) encodePublicKey(sshDir string) error {
	output, err := s.GetPublicKey()

	if err != nil {
		return err
	}

	publicKeyPath := path.Join(sshDir, PublicKeyFileName)

	return os.WriteFile(publicKeyPath, output, 0o600)
}

func (s SSH) GetPublicKeyPath() string {
	return path.Join(s.homeFolder, ".ssh", PublicKeyFileName)
}

func (s SSH) GetPrivateKeyPath() string {
	return path.Join(s.homeFolder, ".ssh", PrivateKeyFileName)
}

func (s SSH) GetPublicKey() ([]byte, error) {
	key, err := ssh.NewPublicKey(s.public)

	if err != nil {
		return nil, err
	}

	return ssh.MarshalAuthorizedKey(key), nil
}
