package main

import (
	"log"

	a "github.com/microapis/auth-api/client"
)

func main() {
	as := a.New("localhost:5010")

	log.Println(as)

	u, err := as.Login("lala@lala.com", "123")
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(u)
}
