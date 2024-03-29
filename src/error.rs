#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("MustHandshakeFirst")]
    MustHandshakeFirst,
    #[error("AlreadyHandshake")]
    AlreadyHandshake,
    #[error("DestinationBufferTooSmall")]
    DestinationBufferTooSmall,
    #[error("IncorrectPacketLength")]
    IncorrectPacketLength,
    #[error("UnexpectedPacket")]
    UnexpectedPacket,
    #[error("WrongPacketType")]
    WrongPacketType,
    #[error("WrongIndex")]
    WrongIndex,
    #[error("WrongKey")]
    WrongKey,
    #[error("InvalidTai64nTimestamp")]
    InvalidTai64nTimestamp,
    #[error("WrongTai64nTimestamp")]
    WrongTai64nTimestamp,
    #[error("InvalidMac")]
    InvalidMac,
    #[error("InvalidAeadTag")]
    InvalidAeadTag,
    #[error("InvalidCounter")]
    InvalidCounter,
    #[error("DuplicateCounter")]
    DuplicateCounter,
    #[error("InvalidPacket")]
    InvalidPacket,
    #[error("NoCurrentSession")]
    NoCurrentSession,
    #[error("IfaceSendFailed")]
    IfaceSendFailed,
}
