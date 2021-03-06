#![cfg_attr(not(feature = "std"), no_std)]

extern crate frame_system as system;
extern crate pallet_balances as balances;
extern crate pallet_timestamp as timestamp;

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::DispatchResult,
    ensure,
    traits::Currency,
    weights::{SimpleDispatchInfo, Weight},
};
use frame_support::storage::IterableStorageMap;

use sp_io::crypto::secp256k1_ecdsa_recover;
use sp_std::prelude::*;
use sp_std::convert::{TryFrom, TryInto};

use core::u64;
use sp_std::vec::Vec;
use system::ensure_signed;

const REWARD_PER_HEAT: u128 = 1000;

pub type Tag = Vec<u8>;
/// merkle-tree root hash
pub type RootHash = Vec<u8>;

#[derive(Encode, Decode, Clone)]
pub struct Sig(pub [u8; 65]);

impl PartialEq for Sig {
    fn eq(&self, other: &Self) -> bool {
        &self.0[..] == &other.0[..]
    }
}

impl sp_std::fmt::Debug for Sig {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter<'_>) -> sp_std::fmt::Result {
        write!(f, "Signature({:?})", &self.0[..])
    }
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct Msg(pub [u8; 32]);

pub trait Trait: system::Trait + timestamp::Trait + balances::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Currency: Currency<Self::AccountId>;
}

#[derive(Encode, Decode, Default, PartialEq, Clone, Eq, Debug)]
pub struct SearchServiceInfo<AccountId, Moment> {
    provider: AccountId,
    name: Vec<u8>,
    url: Vec<u8>,
    tags: Vec<Tag>,
    register_time: Moment,
    heat: u64,
}

#[derive(Encode, Decode, Default, PartialEq, Debug)]
pub struct SearchServiceHash<AccountId, Moment> {
    provider: AccountId,
    root_hash: Option<RootHash>,
    update_time: Moment,
}

decl_storage! {
    trait Store for Module<T: Trait> as Search {
        /// search service name -> search service info
        SearchServices get(get_ss): map hasher(blake2_128_concat) Vec<u8> => SearchServiceInfo<T::AccountId, T::Moment>;
        /// search service name -> search service hash
        SsHashes get(get_hash): map hasher(blake2_128_concat) Vec<u8> => SearchServiceHash<T::AccountId, T::Moment>;
    }
}

decl_event! {
    pub enum Event<T>
    where
    AccountId = <T as system::Trait>::AccountId,
    Moment = <T as timestamp::Trait>::Moment
    {
        /// return a timestamp after uploading searched info
        Timestamp(Moment),
        /// recommend some search service info
        RecommendSsInfo(Vec<SearchServiceInfo<AccountId, Moment>>),
        /// find some search service info by tags
        GetSsInfoByTags(Vec<SearchServiceInfo<AccountId, Moment>>),
        /// find a search service info by name
        GetSsInfoByName(SearchServiceInfo<AccountId, Moment>),
    }
}

decl_error! {
    /// Error for the search module
    pub enum Error for Module<T: Trait> {
        /// when the count of tags more than 10, give an error
        TagsOverflow,
        /// service name exists
        NameExists,
        /// merkle-root hash is illegal
        RootHashIllegal,
        /// signature is illegal
        SignatureIllegal,
        /// permission denied
        PermissionDenied,
        /// signature earlier than update_time
        SignatureTooEarly,
        /// balance converts error
        BalanceConvertErr,
        /// timestamp converts error
        TimestampConvertErr,
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;

        #[weight = SimpleDispatchInfo::FixedNormal(10_000)]
        fn register_search_service(origin, name: Vec<u8>, url: Vec<u8>, tags: Vec<Tag>) -> DispatchResult{
            let provider = ensure_signed(origin)?;
            ensure!(!SearchServices::<T>::contains_key(&name), Error::<T>::NameExists);
            ensure!(tags.len() <= 10, Error::<T>::TagsOverflow);
            let now = <timestamp::Module<T>>::get();
            let ss_info = SearchServiceInfo{
                provider: provider.clone(),
                name: name.clone(),
                url,
                tags,
                register_time: now,
                heat: 0,
            };
            let ss_hash = SearchServiceHash{
                provider,
                root_hash: None,
                update_time: now,
            };
            SearchServices::<T>::insert(&name, &ss_info);
            SsHashes::<T>::insert(&name, &ss_hash);
            Ok(())
        }

        #[weight = SimpleDispatchInfo::FixedNormal(10_000)]
        fn upload_searched_info(
            origin,
            name: Vec<u8>,
            signs: Vec<(Sig, Msg)>,
            root_hash: RootHash,
            last_root_hash: Option<RootHash>
        ) -> DispatchResult {
            let ssp = ensure_signed(origin)?;
            let signs_len = signs.len();
            let now = <timestamp::Module<T>>::get();
            <SsHashes<T>>::try_mutate(&name, |sh| -> DispatchResult {
                ensure!(sh.provider == ssp, Error::<T>::PermissionDenied);
                ensure!(sh.root_hash == last_root_hash, Error::<T>::RootHashIllegal);
                sh.root_hash = Some(root_hash);
                sh.update_time = now;
                Ok(())
            })?;
            let ss_hash = Self::get_hash(&name);
            Self::validate_signatures(signs, ss_hash.update_time)?;
            <SearchServices<T>>::try_mutate(&name, |ssi| -> DispatchResult {
                ssi.heat = signs_len as u64;
                Ok(())
            })?;
            let reward = <T::Balance as TryFrom<u128>>::try_from(signs_len as u128 * REWARD_PER_HEAT).map_err(|_| Error::<T>::BalanceConvertErr)?;
            <balances::Module<T> as Currency<_>>::deposit_creating(&ssp, reward);
            Self::deposit_event(RawEvent::Timestamp(now));
            Ok(())
        }

        #[weight = SimpleDispatchInfo::FixedNormal(10_000)]
        fn recommend_ss(origin) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let ss_vec = SearchServices::<T>::iter()
            .map(|kv| kv.1)
            .take(10)
            .collect::<Vec<SearchServiceInfo<T::AccountId, T::Moment>>>();

            Self::deposit_event(RawEvent::RecommendSsInfo(ss_vec));
            Ok(())
        }

        #[weight = SimpleDispatchInfo::FixedNormal(10_000)]
        fn get_ss_by_tags(origin, tags: Vec<Tag>) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let mut ss_vec = Vec::new();
            let mut it = SearchServices::<T>::iter();
            while let Some(kv) = it.next() {
                let ssi = kv.1;
                if Self::is_in_tags(tags.clone(), ssi.clone().tags) {
                    ss_vec.push(ssi);
                }
            }
            Self::deposit_event(RawEvent::GetSsInfoByTags(ss_vec));
            Ok(())
        }

        #[weight = SimpleDispatchInfo::FixedNormal(10_000)]
        fn get_ss_by_name(origin, ss_name: Vec<u8>) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            Self::deposit_event(RawEvent::GetSsInfoByName(Self::get_ss(ss_name)));
            Ok(())
        }

    }
}

impl<T: Trait> Module<T> {
    fn validate_signatures(
        signs: Vec<(Sig, Msg)>,
        ts: T::Moment,
    ) -> DispatchResult {
        let last_ts: u64 = <T::Moment as TryInto<u64>>::try_into(ts).map_err(|_| Error::<T>::TimestampConvertErr)?;
        let mut sign = signs.iter();
        while let Some((sig, msg)) = sign.next() {
            let sign_ts = Self::bytes_to_u64(msg.0[0..8].as_ref());
            ensure!(sign_ts >= last_ts, Error::<T>::SignatureTooEarly);
            ensure!(
                secp256k1_ecdsa_recover(&sig.0, &msg.0).is_ok(),
                Error::<T>::SignatureIllegal
            );
        }
        Ok(())
    }

    fn is_in_tags(targets: Vec<Tag>, range: Vec<Tag>) -> bool {
        let mut target_it = targets.iter();
        let mut range_it = range.iter();
        while let Some(target) = target_it.next() {
            let mut exist = false;
            while let Some(tag) = range_it.next() {
                if target == tag {
                    exist = true;
                    break;
                }
            }
            if !exist {
                return false;
            }
        }
        true
    }

    fn bytes_to_u64(data: &[u8]) -> u64 {
        let mut u8_8: [u8; 8] = [0_u8; 8];
        u8_8.clone_from_slice(data);
        u64::from_be_bytes(u8_8)
    }
}
