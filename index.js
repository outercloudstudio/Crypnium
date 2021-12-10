const net = require('net')
const security = require('./security')
const { handshakePort, handshakeIP } = require('./config')
const readline = require('readline')
const rl = readline.createInterface({
	input: process.stdin,
	output: process.stdout
})

class Message {
  message = undefined
  authorHash = undefined
  validHash = undefined
  upvotes = 0

  constructor(_message, author) {
    this.message = _message
    this.authorHash = hash(_message + author)
    this.validHash = hash(_message + this.authorHash + this.upvotes.toString())
  }

  validate() {
    const currentValidHash = hash(this.message + this.authorHash + this.upvotes.toString())

    return currentValidHash == this.validHash
  }

  checkAuthor(author) {
    const currentAuthorHash = hash(this.message + author)

    return currentAuthorHash == this.authorHash
  }

  toString() {
    return this.message + '|' + this.authorHash + '|' + this.validHash + '|' + this.upvotes.toString()
  }

  recreate(stringed) {
    const values = stringed.split('|')

    if (values.length != 4) {
      return false
    }

    this.message = values[0]
    this.authorHash = values[1]
    this.validHash = values[2]

    const upvotes = parseInt(values[3])

    if (isNaN(upvotes)) {
      return false
    }

    this.upvotes = upvotes
  }
}

class PeerManager {
  readCommandLineAndWrite(socket) {
    rl.question('Enter Message: ', message => {
      socket.write(message)
  
      this.readCommandLineAndWrite(socket)
    })
  }

  listenForPeer(port){
    this.peerListenServer = net.createServer()

    this.peerListenServer.listen(port, () => {
      console.log('Listen Server is running on port ' + this.peerListenServer.address().port + '!')  
    })

    let connectedSocket

    this.peerListenServer.on('connection', function (sock) {
      console.log('Listen CONNECTED: ' + sock.remoteAddress + ':' + sock.remotePort)

      if (connectedSocket) {
        console.log('Listen DENYING: ' + sock.remoteAddress + ':' + sock.remotePort)

        sock.destroy()
      } else {
        connectedSocket = sock

        sock.on('data', function (data) {
          console.log('Listen DATA ' + sock.remoteAddress + ': ' + data);
        })
      }

      sock.on('close', function (data) {
        console.log('Listen CLOSED: ' + sock.remoteAddress + ' ' + sock.remotePort)
      })

      sock.on('error', err => {
        console.log('Listen ERROR: ' + err)
      })
    })
  }

  connectToPeer(ip, port){
    this.peerSocket = new net.Socket()

    this.peerSocket.on('error', err => {
      console.log('Peer Socket ERROR: ' + err)
    })

    this.peerSocket.connect(port, ip, () => {
      console.log('Peer Socket Connected')

      this.peerSocket.on('data', data => {
        console.log('Peer Data received in state ' + state + ': ' + data)
      })

      this.readCommandLineAndWrite(this.peerSocket)
    })
  }
  
  constructor(secret, targetSecret) {
    this.secret = secret
    this.targetSecret = targetSecret

    const socket = new net.Socket()

    socket.on('error', err => {
      console.log('ERROR: ' + err)
    })

    socket.connect(handshakePort, handshakeIP, () => {
      let state = 'WFK'

      let publicEncryptionKey = ''

      //console.log('Connected')

      socket.on('data', data => {
        console.log('Data received in state ' + state + '!')

        if (state == 'WFK') {
          this.publicEncryptionKey = data.toString()

          const encryptedSecret = security.encrypt(this.secret, this.publicEncryptionKey)

          socket.write(encryptedSecret)

          state = 'WFC'
        } else if (state == 'WFC') {
          const encryptedData = security.encrypt(this.targetSecret, this.publicEncryptionKey)

          this.encryptionKeys = security.keyPair()

          socket.write(encryptedData + '|' + this.encryptionKeys[0])

          state = 'WFNAT'
        } else if (state == 'WFNAT') {
          const targetPeerData = security.decrypt(data.toString(), this.encryptionKeys[1]).split('|')

          socket.end('Closing For NAT!')

          console.log('Attempting to NAT punch to ' + targetPeerData[0] + ':' + targetPeerData[1])

          this.listenForPeer(socket.address().port)

          this.connectToPeer(targetPeerData[0], parseInt(targetPeerData[1]))
        }
      })
    })
  }
}

//const peerSecret = security.randomBytes(1)

const peer1 = new PeerManager('admin', 'admin')