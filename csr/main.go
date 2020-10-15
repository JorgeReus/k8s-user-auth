package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/golang-collections/collections/set"
	gomail "gopkg.in/mail.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	k8sCertsV1 "k8s.io/api/certificates/v1"
	k8sMetaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sInformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"os"
	"path/filepath"
	"text/template"
	"time"
)

type RSAData struct {
	Csr *[]byte
	Key *[]byte
}
type KubeConfigData struct {
	CAKey                 string
	ClusterCA             string
	ClusterEndpoint       string
	ClusterName           string
	User                  string
	UserEmail             string
	ClientCertificateData string
	ClientKeyData         string
}

var keyData = make(map[string]*[]byte)
var currentContext string
var kubeConfigTmplDat, _ = ioutil.ReadFile("./templates/kubeconfig.tmpl")
var kubeConfigTemplate = string(kubeConfigTmplDat)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func createKubeConfig(data KubeConfigData) {
	t, err := template.New("kubeconfig").Parse(kubeConfigTemplate)
	check(err)
	resultFile := fmt.Sprintf("/tmp/%v.kubeconfig", data.UserEmail)
	f, err := os.Create(resultFile)
	check(err)
	w := bufio.NewWriter(f)
	err = t.Execute(w, data)
	check(err)
	err = w.Flush()
	check(err)
	sendEmail("admin@example.com", data.UserEmail, resultFile)
}

func getKubeConfig() *rest.Config {
	var kubeConfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeConfig = flag.String("kubeConfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeConfig file")
	} else {
		kubeConfig = flag.String("kubeConfig", "", "absolute path to the kubeConfig file")
	}
	flag.Parse()
	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	defaultConfig, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	check(err)
	currentContext = defaultConfig.CurrentContext
	return config
}

func getPendingCertificatesList(ctx context.Context, k8sClient *kubernetes.Clientset) *[]k8sCertsV1.CertificateSigningRequest {
	csrList, err := k8sClient.CertificatesV1().CertificateSigningRequests().List(ctx, k8sMetaV1.ListOptions{})
	check(err)
	var pendingCertificates []k8sCertsV1.CertificateSigningRequest
	for _, csr := range csrList.Items {
		if csr.Status.Certificate == nil {
			pendingCertificates = append(pendingCertificates, csr)
		}
	}
	return &pendingCertificates
}

func approveCsr(ctx context.Context, k8sClient *kubernetes.Clientset, csr k8sCertsV1.CertificateSigningRequest) {
	csr.Status.Conditions = append(csr.Status.Conditions, k8sCertsV1.CertificateSigningRequestCondition{
		Type:           k8sCertsV1.CertificateApproved,
		Reason:         "Approved by CICD",
		Message:        "This CSR was approved by CICD",
		Status:         "True",
		LastUpdateTime: k8sMetaV1.Now(),
	})
	_, err := k8sClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, &csr, k8sMetaV1.UpdateOptions{})
	check(err)
}

func getCsrBytes(commonName string, organization string) *RSAData {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	keyBytes := getPrivateKeyPEMBytes(key)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		panic(err)
	}

	subj := pkix.Name{
		CommonName:   commonName,
		Organization: []string{organization},
	}

	templateCsr := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	var b bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &templateCsr, key)
	err = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	sliceAddr := b.Bytes()
	var result = RSAData{
		Csr: &sliceAddr,
		Key: keyBytes,
	}
	return &result
}

func getPrivateKeyPEMBytes(key *rsa.PrivateKey) *[]byte {
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	var b bytes.Buffer
	err := pem.Encode(&b, privateKey)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		panic(err)
	}
	var rsaBytes = b.Bytes()
	return &rsaBytes
}

func listenCsrUpdates(k8sConfig *rest.Config, k8sClient *kubernetes.Clientset) {
	kubeInformerFactory := k8sInformers.NewSharedInformerFactory(k8sClient, time.Second*30)
	csrInformer := kubeInformerFactory.Certificates().V1().CertificateSigningRequests().Informer()
	users := set.New()
	for k := range keyData {
		users.Insert(k)
	}

	csrInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			var csr = newObj.(*k8sCertsV1.CertificateSigningRequest)
			if csr.Status.Certificate != nil && users.Has(csr.Name) {
				var caKey, caData string
				if k8sConfig.CAData == nil {
					caKey = "certificate-authority-data"
					dat, err := ioutil.ReadFile(k8sConfig.CAFile)
					check(err)
					caData = base64.StdEncoding.EncodeToString(dat)
				} else {
					caKey = "certificate-authority-data"
					caData = base64.StdEncoding.EncodeToString(k8sConfig.CAData)
				}
				var data = KubeConfigData{
					CAKey:                 caKey,
					ClusterCA:             caData,
					ClusterEndpoint:       k8sConfig.Host,
					ClusterName:           currentContext,
					User:                  csr.Spec.Username,
					UserEmail:             csr.Name,
					ClientCertificateData: base64.StdEncoding.EncodeToString(csr.Status.Certificate),
					ClientKeyData:         base64.StdEncoding.EncodeToString(*keyData[csr.Name]),
				}

				createKubeConfig(data)
				fmt.Printf("Kubeconfig created for user: %v\n", csr.Name)
				users.Remove(csr.Name)
			}
		},
	})
	stop := make(chan struct{})
	defer close(stop)
	kubeInformerFactory.Start(stop)
	for {
		if users.Len() == 0 {
			break
		}
		time.Sleep(time.Second)
	}
}

func sendEmail(from string, to string, filename string) {
	// run fake-smtp-server for example
	username := "username"
	password := "password"

	smtpHost := "0.0.0.0"
	smtpPort := 1025

	m := gomail.NewMessage()

	// Set E-Mail sender
	m.SetHeader("From", from)

	// Set E-Mail receivers
	m.SetHeader("To", to)

	// Set E-Mail subject
	m.SetHeader("Subject", "Kubeconfig")

	// Set E-Mail body. You can set plain text or html with text/html
	m.SetBody("text/plain", "New kubeconfig")
	m.Attach(filename)

	// Settings for SMTP server
	d := gomail.NewDialer(smtpHost, smtpPort, username, password)

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// Now send E-Mail
	if err := d.DialAndSend(m); err != nil {
		fmt.Println(err)
		panic(err)
	}
}

func main() {
	var k8sConfig = getKubeConfig()
	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	check(err)
	var ctx = context.TODO()
	// Read the yml usermap
	m := make(map[string]map[string][]string)
	var data, _ = ioutil.ReadFile("./certs.yaml")
	err = yaml.Unmarshal(data, &m)
	check(err)
	// Process the users
	for role, userMap := range m["users"] {
		for _, user := range userMap {
			// Get the CSR for the user
			_, err := k8sClient.CertificatesV1().CertificateSigningRequests().Get(ctx, user, k8sMetaV1.GetOptions{})
			// If the csr for the Common Name (user) doesn't exist, create a new CSR
			var rsaData = getCsrBytes(user, role)
			if err != nil {
				fmt.Printf("Processing user: %s whose role is %s\n", user, role)
				keyData[user] = rsaData.Key
				var csr = k8sCertsV1.CertificateSigningRequest{}
				csr.Name = user
				csr.Spec.Groups = []string{"system:authenticated"}
				csr.Spec.Usages = []k8sCertsV1.KeyUsage{"client auth"}
				csr.Spec.Request = *rsaData.Csr
				csr.Spec.SignerName = "kubernetes.io/kube-apiserver-client"
				_, err := k8sClient.CertificatesV1().CertificateSigningRequests().Create(ctx, &csr, k8sMetaV1.CreateOptions{})
				check(err)
			}
		}
	}
	//Listen for the csr's certificates creation
	if len(keyData) > 0 {
		defer listenCsrUpdates(k8sConfig, k8sClient)
	} else {
		fmt.Println("No certificate events to listen")
	}
	//Get the CSR List of pending certificates
	var csrList = *getPendingCertificatesList(ctx, k8sClient)
	//Approve the certificates if the data matches
	for _, csr := range csrList {
		approveCsr(ctx, k8sClient, csr)
	}
}
