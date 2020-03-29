#![cfg_attr(not(feature = "std"), no_std)]

extern crate frame_system as system;

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::DispatchResult,
    ensure,
    weights::{
        ClassifyDispatch, DispatchClass, DispatchInfo, PaysFee, SimpleDispatchInfo, WeighData,
        Weight,
    },
};
use keccak_hasher::KeccakHasher;
use sp_core::ed25519::{Pair, Public, Signature};
use system::{ensure_signed};
use core::u64;

const REWARD_PER_HEAT: u128 = 1000;
const ALICE: &'static str = "";

pub type Tag = Vec<u8>;
/// merkle-tree root hash
pub type RootHash = KeccakHasher;

pub trait Trait: system::Trait + timestamp::Trait + balances::Trait{
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Currency: Currency<Self::AccountId>;
}

#[derive(Encode, Decode, Default, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct SearchServiceInfo<AccountId, Moment> {
    provider: AccountId,
    name: Vec<u8>,
    url: Vec<u8>,
    tags: Vec<Tag>,
    register_time: Moment,
    heat: u64,
}

#[derive(Encode, Decode, Default, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct SearchServiceHash<AccountId, Moment> {
    provider: AccountId,
    root_hash: Option<RootHash>,
    update_time: Moment,
}

decl_storage! {
    trait Store for Module<T: Trait> as Search {
        /// search service name -> search service info
        SearchServices get(get_ss): map Vec<u8> => SearchServiceInfo<T::AccountId, T::Moment>;
        /// search service name -> search service hash
        SsHashes get(get_hash): map Vec<u8> => SearchServiceHash<T::AccountId, T::Moment>;
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
    pub enum Error for Module<T: Trait> {
        /// when the count of tags more than 10, give an error
        TagsOverflow,
        /// service name exists
        NameExists,
        /// merkle-root hash is illegal
        RootHashIllegal,
        /// signature is illegal
        SignatureIllegal(Vec<u8>),
        /// permission denied
        PermissionDenied,
        /// signature earlier than update_time
        SignatureTooEarly,
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin{
        type Error = Error<T>;

        fn deposit_event<T>() = default;

        fn register_search_service(origin, name: Vec<u8>, url: Vec<u8>, tags: Vec<Tag>) -> DispatchResult{
            let provider = ensure_signed(origin)?;
            ensure!(!SearchServices::<T>::contains_key(name), Error::<T>::NameExists);
            ensure!(tags.len() <= 10, Error::<T>::TagsOverflow);
            let now = <timestamp::Module<T>>::get();
            let ss_info = SearchServiceInfo{
                provider: provider.clone(),
                name,
                url,
                tags,
                register_time: now,
                heat: 0,
            }
            let ss_hash = SearchServiceHash{
                provider,
                root_hash: None,
                update_time: now,
            }
            SearchServices::<T>::insert(&name, &ss_info);
            SsHashes::<T>::insert(&name, &ss_hash);
            Ok(())
        }

        fn upload_searched_info(
            origin,
            name: Vec<u8>,
            signs: Vec<(Pair::Signature, Vec<u8>, Pair::Public)>,
            root_hash: RootHash,
            last_root_hash: Option<RootHash>
        ) -> DispatchResult {
            let ssp = ensure_signed(origin)?;
            let signs_len = signs.len();
            let now = <timestamp::Module<T>>::get();
            SsHashes::<T>::try_mutate(&name, |sh| {
                ensure!(sh.provider == ssp, Error::<T>::PermissionDenied);
                ensure!(sh.root_hash == last_root_hash, Error::<T>::RootHashIllegal);
                *sh.root_hash = root_hash;
                *sh.update_time = now;
            })?;
            SearchServices::<T>::try_mutate(&name, |ssi| {
                Self::validate_signatures(signs, ssi.update_time)?;
                *ssi.heat = signs_len;
            })?;
            /// reward ssp
            <balances::Module<T> as Currency<_>>::transfer(ALICE, ssp, REWARD_PER_HEAT * signs_len);
            Self::deposit_event(RawEvent::Timestamp(now));
            Ok(())
        }

        fn recommend_ss(origin) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let ss_vec = SearchServices::<T>::iter()
            .map(|kv| kv.1)
            .take(10)
            .collect::<Vec<SearchServiceInfo<T::AccountId, T::Moment>>>();

            Self::deposit_event(RawEvent::RecommendSsInfo(ss_vec));
            Ok(())
        }

        fn get_ss_by_tags(origin, tags: Vec<Tag>) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let mut ss_vec = Vec::new();
            let mut it = SearchServices::<T>::iter();
            while let Some(kv) = it.next() {
                let ssi = kv.1;
                if Self::is_in_tags(tags, ssi.tags) {
                    ss_vec.push(ssi);
                }
            }
            Self::deposit_event(RawEvent::GetSsInfoByTags(ss_vec));
            Ok(())
        }

        fn get_ss_by_name(origin, ss_name: Vec<u8>) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            Self::deposit_event(RawEvent::GetSsInfoByName(Self::get_ss(ss_name)));
            Ok(())
        }
    }

}

impl<T: Trait> Module<T> {
    fn validate_signatures(signs: Vec<(Pair::Signature, Vec<u8>, Pair::Public)>, ts: T::Moment) -> DispatchResult {
        let last_ts: u64 = ts.try_into()?;
        let mut sign = signs.iter();
        while let Some(sg) = sign.next() {
            let sign_ts = Self::bytes_to_u64(sg.1.clone().as_ref());
            ensure!(sign_ts >= last_ts, Error::<T>::SignatureTooEarly);
            ensure!(Pair::verify(&sg.0, sg.1.clone(), &sg.2), Error::<T>::SignatureIllegal(sg.1));
        }
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