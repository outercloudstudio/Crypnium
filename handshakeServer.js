const net = require('net')
const security = require('./security')
const { handshakePort, handshakeIP } = require('./config')

const server = net.createServer()

server.listen(handshakePort, () => {
    //console.log('Handshake Server is running on port ' + handshakePort + '!')
})

let sockets = []
let socketStates = []
let socketSecrets = []
let socketEncryptionKeys = []

server.on('connection', function(sock) {
    console.log('CONNECTED: ' + sock.remoteAddress + ':' + sock.remotePort)
    sockets.push(sock)
    socketStates.push('WFS')
    socketSecrets.push('')
    socketEncryptionKeys.push('')
    
    const keys = security.keyPair()

    sock.write(keys[0])

    sock.on('data', function(data) {
        let index = sockets.findIndex(function(o) {
          return o.remoteAddress === sock.remoteAddress && o.remotePort === sock.remotePort
        })

        console.log('Data received from ' + sock.remoteAddress + ' in state ' + socketStates[index] + '!')

        if (index !== -1){
          if(socketStates[index] == 'WFS'){
            const decryption = security.decrypt(data.toString(), keys[1])

            if(decryption){
              socketSecrets[index] = [decryption]

              sock.write('OK')

              socketStates[index] = 'WFTS'
            }else{
              console.log('DENYING: ' + sock.remoteAddress + ':' + sock.remotePort)
              sock.destroy()
            }
          }else if(socketStates[index] == 'WFTS'){
            socketSecrets[index].push(security.decrypt(data.toString().split('|')[0], keys[1]))

            socketEncryptionKeys[index] = data.toString().split('|')[1]

            socketStates[index] = 'WFSS'

            let found = false

            for(let i = 0; i < sockets.length; i++){
              if(i != index){
                if(socketStates[i] == 'WFSS'){
                  if(socketSecrets[i][0] == socketSecrets[index][1] && socketSecrets[i][1] == socketSecrets[index][0]){
                    console.log('Found peer with matching secrets!')
                    
                    let otherSocketMessage = security.encrypt(sockets[index].remoteAddress + '|' + sockets[index].remotePort, socketEncryptionKeys[i])

                    sockets[i].write(otherSocketMessage)

                    let thisSocketMessage = security.encrypt(sockets[i].remoteAddress + '|' + sockets[i].remotePort, socketEncryptionKeys[index])

                    sockets[index].write(thisSocketMessage)

                    found = true

                    break
                  }
                }
              }
            }

            if(!found){
              console.log('Could not find peer with matching secrets!')
            }
          }
        }
    })

    sock.on('close', function(data) {
        let index = sockets.findIndex(function(o) {
            return o.remoteAddress === sock.remoteAddress && o.remotePort === sock.remotePort
        })
        if (index !== -1){
          sockets.splice(index, 1)
          socketSecrets.splice(index, 1)
          socketStates.splice(index, 1)
          socketEncryptionKeys.splice(index, 1)
        }

        console.log('CLOSED: ' + sock.remoteAddress + ' ' + sock.remotePort)
    })

    sock.on('error', err => {
        console.log('ERROR: ' + err)
    })
})