pub trait Cryptor: Sized + Send + Sync {
    fn init_handshake(
        own_prikey: crate::x25519::StaticSecret,
        node_pubkey: crate::x25519::PublicKey,
    ) -> Result<(Self, Vec<u8>), crate::Error>;
    fn handle_handshake(
        own_prikey: crate::x25519::StaticSecret,
        own_pubkey: crate::x25519::PublicKey,
        packet: &[u8],
    ) -> Result<(Self, Option<Vec<u8>>), crate::Error>;
    fn handle_handshake_response(&mut self, packet: &[u8]) -> Result<(), crate::Error>;
    fn on_send<'a>(
        &mut self,
        packet: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], crate::Error>;
    fn on_recv<'a>(
        &mut self,
        packet: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], crate::Error>;

    fn get_peer_public(&self) -> Result<crate::x25519::PublicKey /* peer pubkey */, crate::Error>;
}
