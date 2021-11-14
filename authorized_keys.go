package ssh

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/SSH-Management/utils"
)

func CreateAuthorizedKeys(authorizedKeys string, userId, groupId int, perm int, exec func(file *os.File) error) error {
	p, err := utils.GetAbsolutePath(authorizedKeys)

	if err != nil {
		return err
	}

	sshDir := filepath.Dir(p)

	// SSH directory doesn't exist
	if !utils.FileExists(sshDir) {
		_, err = utils.CreateDirectory(sshDir, 0o700)
		if err := os.Chown(sshDir, userId, groupId); err != nil {
			return err
		}
	}

	// authorized_keys file doesn't exist
	if !utils.FileExists(p) {
		f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o644)

		if err != nil {
			return err
		}

		if err := f.Close(); err != nil {
			return err
		}
	}

	f, err := os.OpenFile(p, perm, 0o644)

	if err != nil {
		return err
	}

	defer f.Close()

	if err := exec(f); err != nil {
		if err = f.Chown(userId, groupId); err != nil {
			return err
		}

		return err
	}

	if err = f.Chown(userId, groupId); err != nil {
		return err
	}

	return nil
}

func AddToAuthorizedKeys(authorizedKeys, publicKey string, userId, groupId int) error {
	write := func(file *os.File) error {
		_, err := file.WriteString(fmt.Sprintf("%s\n", publicKey))

		if err != nil {
			return err
		}

		return file.Sync()
	}

	err := CreateAuthorizedKeys(
		authorizedKeys,
		userId,
		groupId,
		os.O_APPEND|os.O_WRONLY,
		write,
	)

	if err != nil {
		return err
	}

	return err
}

//
//func RemoveFromAuthorizedKeys(authorizedKeys, publicKey string, userId, groupId int) error{
//tmp, err := os.CreateTemp("ssh", "authorized_keys")
//
//
//if err != nil{
//return nil
//}
//
//defer tmp.Close()
//
//err := CreateAuthorizedKeys(authorizedKeys, userId, groupId, os.O_CREATE|os.O_RDWR)
//
//if err != nil{
//return err
//}
//
//
//authorizedKeysScanner := bufio.NewScanner(f)
//
//for authorizedKeysScanner.Scan(){
// line := authorizedKeysScanner.Text()
//if line != publicKey{
//tmp.WriteString(line)
//}
//}
//
//_, err = f.Seek(0, io.SeekStart)
//
//if err != nil{
//return nil
//}
//
//if err := f.Truncate(0); err != nil{
//return err
//}
//
//return err
//}
