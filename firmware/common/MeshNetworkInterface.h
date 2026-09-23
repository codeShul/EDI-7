#ifndef MESH_NETWORK_INTERFACE_H
#define MESH_NETWORK_INTERFACE_H

#include "ApplicationPacket.h"

// Abstract Mesh Network Interface for ESP32
class MeshNetworkInterface {
public:
    virtual ~MeshNetworkInterface() {}
    
    // Initialize mesh node hardware and radio
    virtual bool initialize(uint8_t node_id) = 0;
    
    // Send application packet across the mesh
    virtual bool sendPacket(const ApplicationPacket& packet) = 0;
    
    // Process incoming packet queue
    virtual void processIncoming() = 0;
    
    // Isolate/Blacklist a target node ID from mesh communication
    virtual void isolateNode(uint8_t target_node_id) = 0;
    
    // Restore a previously isolated node
    virtual void restoreNode(uint8_t target_node_id) = 0;
    
    // Check if node is isolated locally
    virtual bool isIsolated(uint8_t target_node_id) const = 0;
};

#endif // MESH_NETWORK_INTERFACE_H
