#[allow(unused)]
pub struct RawCryptor {
    data: Option<std::ptr::NonNull<()>>,
    vtable: &'static VTable,
}

unsafe impl Send for RawCryptor {}

unsafe impl Sync for RawCryptor {}

impl RawCryptor {
    pub fn new<C: crate::Cryptor>() -> Self {
        let vtable = &VTable {
            init_handshake: |own_prikey: crate::x25519::StaticSecret,
                             node_pubkey: crate::x25519::PublicKey|
             -> Result<(std::ptr::NonNull<()>, Vec<u8>), crate::Error> {
                C::init_handshake(own_prikey, node_pubkey).map(|(crypto, hs)| {
                    let ptr = unsafe {
                        std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(crypto))).cast()
                    };
                    (ptr, hs)
                })
            },
            handle_handshake: |own_prikey: crate::x25519::StaticSecret,
                               node_pubkey: crate::x25519::PublicKey,
                               packet: &[u8]|
             -> Result<
                (std::ptr::NonNull<()>, Option<Vec<u8>>),
                crate::Error,
            > {
                C::handle_handshake(own_prikey, node_pubkey, packet).map(|(crypto, hs)| {
                    let ptr = unsafe {
                        std::ptr::NonNull::new_unchecked(Box::into_raw(Box::new(crypto))).cast()
                    };
                    (ptr, hs)
                })
            },
            handle_handshake_response: for<'a> |this: *mut (),
                                                packet: &'a [u8]|
                     -> Result<(), crate::Error> {
                C::handle_handshake_response(unsafe { &mut *this.cast::<C>() }, packet)
            },
            on_send: for<'a, 'b> |this: *mut (),
                                  packet: &'b [u8],
                                  dst: &'a mut [u8]|
                         -> Result<&'a mut [u8], crate::Error> {
                C::on_send(unsafe { &mut *this.cast::<C>() }, packet, dst)
            },
            on_recv: for<'a, 'b> |this: *mut (),
                                  packet: &'b [u8],
                                  dst: &'a mut [u8]|
                         -> Result<&'a mut [u8], crate::Error> {
                C::on_recv(unsafe { &mut *this.cast::<C>() }, packet, dst)
            },
            get_peer_public: |this: *const ()| -> Result<
                crate::x25519::PublicKey, /* peer pubkey */
                crate::Error,
            > { C::get_peer_public(unsafe { &*this.cast::<C>() }) },
            drop: |this: *mut ()| drop(unsafe { Box::from_raw(this.cast::<C>()) }),
        };
        RawCryptor { data: None, vtable }
    }

    pub fn init_handshake(
        &mut self,
        own_prikey: crate::x25519::StaticSecret,
        node_pubkey: crate::x25519::PublicKey,
    ) -> Result<Vec<u8>, crate::Error> {
        if self.data.is_some() {
            return Err(crate::Error::AlreadyHandshake);
        };
        (self.vtable.init_handshake)(own_prikey, node_pubkey).map(|(this, hs)| {
            self.data = Some(this);
            hs
        })
    }

    pub fn handle_handshake(
        &mut self,
        own_prikey: crate::x25519::StaticSecret,
        own_pubkey: crate::x25519::PublicKey,
        packet: &[u8],
    ) -> Result<Option<Vec<u8>>, crate::Error> {
        if self.data.is_some() {
            return Err(crate::Error::AlreadyHandshake);
        };
        (self.vtable.handle_handshake)(own_prikey, own_pubkey, packet).map(|(this, hs)| {
            self.data = Some(this);
            hs
        })
    }

    pub fn handle_handshake_response(&mut self, packet: &[u8]) -> Result<(), crate::Error> {
        let this = self.data.ok_or(crate::Error::MustHandshakeFirst)?;
        (self.vtable.handle_handshake_response)(this.as_ptr(), packet)
    }

    pub fn on_send<'a>(
        &mut self,
        packet: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], crate::Error> {
        let this = self.data.ok_or(crate::Error::MustHandshakeFirst)?;
        (self.vtable.on_send)(this.as_ptr(), packet, dst)
    }

    pub fn on_recv<'a>(
        &mut self,
        packet: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], crate::Error> {
        let this = self.data.ok_or(crate::Error::MustHandshakeFirst)?;
        (self.vtable.on_recv)(this.as_ptr(), packet, dst)
    }

    pub fn get_peer_public(
        &self,
    ) -> Result<crate::x25519::PublicKey /* peer pubkey */, crate::Error> {
        let this = self.data.ok_or(crate::Error::MustHandshakeFirst)?;
        (self.vtable.get_peer_public)(this.as_ptr())
    }
}

impl Clone for RawCryptor {
    fn clone(&self) -> Self {
        Self {
            data: None,
            vtable: self.vtable,
        }
    }
}

impl Drop for RawCryptor {
    fn drop(&mut self) {
        if let Some(this) = self.data {
            unsafe { (self.vtable.drop)(this.as_ptr()) }
        }
    }
}

type PacketHandler =
    for<'a, 'b> fn(*mut (), &'b [u8], &'a mut [u8]) -> Result<&'a mut [u8], crate::Error>;

struct VTable {
    init_handshake: fn(
        crate::x25519::StaticSecret,
        crate::x25519::PublicKey,
    ) -> Result<(std::ptr::NonNull<()>, Vec<u8>), crate::Error>,
    handle_handshake: fn(
        crate::x25519::StaticSecret,
        crate::x25519::PublicKey,
        &[u8],
    ) -> Result<(std::ptr::NonNull<()>, Option<Vec<u8>>), crate::Error>,
    handle_handshake_response: fn(*mut (), &[u8]) -> Result<(), crate::Error>,
    on_send: PacketHandler,
    on_recv: PacketHandler,
    get_peer_public:
        fn(*const ()) -> Result<crate::x25519::PublicKey /* peer pubkey */, crate::Error>,
    drop: unsafe fn(*mut ()),
}

#[cfg(test)]
mod test {
    use crate::Cryptor;
    use crate::RawCryptor;
    use rand_core::OsRng;

    fn gen_private() -> crate::x25519::StaticSecret {
        crate::x25519::StaticSecret::random_from_rng(OsRng)
    }

    fn gen_public() -> crate::x25519::PublicKey {
        x25519_dalek::PublicKey::from(&crate::x25519::StaticSecret::random_from_rng(OsRng))
    }

    struct C1 {}

    impl Cryptor for C1 {
        fn init_handshake(
            _own_prikey: crate::x25519::StaticSecret,
            _node_pubkey: crate::x25519::PublicKey,
        ) -> Result<(Self, Vec<u8>), crate::Error> {
            println!("c1 init_handshake");

            Ok((C1 {}, vec![1]))
        }

        fn handle_handshake(
            _own_prikey: crate::x25519::StaticSecret,
            _own_pubkey: crate::x25519::PublicKey,
            _packet: &[u8],
        ) -> Result<(Self, Option<Vec<u8>>), crate::Error> {
            println!("c1 handle_handshake");

            Ok((C1 {}, Some(vec![1])))
        }

        fn handle_handshake_response(&mut self, _packet: &[u8]) -> Result<(), crate::Error> {
            println!("c1 handle_handshake_response");

            Ok(())
        }

        fn on_send<'a>(
            &mut self,
            _packet: &[u8],
            dst: &'a mut [u8],
        ) -> Result<&'a mut [u8], crate::Error> {
            println!("c1 on_send");
            dst[0] = 1;
            Ok(dst)
        }

        fn on_recv<'a>(
            &mut self,
            _packet: &[u8],
            dst: &'a mut [u8],
        ) -> Result<&'a mut [u8], crate::Error> {
            println!("c1 on_recv");
            dst[0] = 1;
            Ok(dst)
        }

        fn get_peer_public(
            &self,
        ) -> Result<crate::x25519::PublicKey /* peer pubkey */, crate::Error> {
            println!("c1 get_peer_public");

            Ok(x25519_dalek::PublicKey::from(
                &crate::x25519::StaticSecret::random_from_rng(OsRng),
            ))
        }
    }

    struct C2 {}

    impl Cryptor for C2 {
        fn init_handshake(
            _own_prikey: crate::x25519::StaticSecret,
            _node_pubkey: crate::x25519::PublicKey,
        ) -> Result<(Self, Vec<u8>), crate::Error> {
            println!("c2 init_handshake");

            Ok((C2 {}, vec![2]))
        }

        fn handle_handshake(
            _own_prikey: crate::x25519::StaticSecret,
            _own_pubkey: crate::x25519::PublicKey,
            _packet: &[u8],
        ) -> Result<(Self, Option<Vec<u8>>), crate::Error> {
            println!("c2 handle_handshake");

            Ok((C2 {}, Some(vec![2])))
        }

        fn handle_handshake_response(&mut self, _packet: &[u8]) -> Result<(), crate::Error> {
            println!("c2 handle_handshake_response");

            Ok(())
        }

        fn on_send<'a>(
            &mut self,
            _packet: &[u8],
            dst: &'a mut [u8],
        ) -> Result<&'a mut [u8], crate::Error> {
            println!("c2 on_send");
            dst[0] = 2;
            Ok(dst)
        }

        fn on_recv<'a>(
            &mut self,
            _packet: &[u8],
            dst: &'a mut [u8],
        ) -> Result<&'a mut [u8], crate::Error> {
            println!("c2 on_recv");
            dst[0] = 2;
            Ok(dst)
        }

        fn get_peer_public(
            &self,
        ) -> Result<crate::x25519::PublicKey /* peer pubkey */, crate::Error> {
            println!("c2 get_peer_public");

            Ok(x25519_dalek::PublicKey::from(
                &crate::x25519::StaticSecret::random_from_rng(OsRng),
            ))
        }
    }

    #[test]
    fn raw_crypto() {
        let mut c1 = RawCryptor::new::<C1>();
        let mut c2 = RawCryptor::new::<C2>();

        let init_handshake = c1.init_handshake(gen_private(), gen_public()).unwrap();
        assert_eq!(init_handshake, vec![1]);

        let handle_handshake = c2
            .handle_handshake(gen_private(), gen_public(), &[0])
            .unwrap();
        assert_eq!(handle_handshake, Some(vec![2]));

        c1.handle_handshake_response(&[0]).unwrap();
        c2.handle_handshake_response(&[0]).unwrap();

        let dst = &mut [0, 0, 0];

        let on_send = c1.on_send(&[0], dst).unwrap();
        assert_eq!(on_send, vec![1, 0, 0]);
        let on_send = c2.on_send(&[0], dst).unwrap();
        assert_eq!(on_send, vec![2, 0, 0]);

        let on_recv = c1.on_recv(&[0], dst).unwrap();
        assert_eq!(on_recv, vec![1, 0, 0]);
        let on_recv = c2.on_recv(&[0], dst).unwrap();
        assert_eq!(on_recv, vec![2, 0, 0]);

        let get_peer_public = c1.get_peer_public().unwrap();
        println!("c1 get_peer_public: {:?}", get_peer_public);
        let get_peer_public = c2.get_peer_public().unwrap();
        println!("c2 get_peer_public: {:?}", get_peer_public);
    }
}
