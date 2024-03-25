use yew::prelude::*;
use yew_router::history::History;
use yew_router::history::HashHistory;
use yewdux::functional::use_store;

use crate::app::UserState;
use crate::components::auth::register_form::RegisterForm;

#[function_component(Register)]
pub fn login() -> Html {
    let (user_state, _user_dispatch) = use_store::<UserState>();

    use_effect(move || {
        if user_state.user_info.uuid != String::new() {
            HashHistory::new().push("/")
        }
    });

    html! {
        <div class="col-span-12 row-span-24 flex flex-col justify-center items-center h-full">
            <RegisterForm />
            <div tabindex={0} class="cursor-pointer text-blue-600 dark:text-blue-400 underline
                    focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-3"
                    onclick={move |_| {HashHistory::new().push("/login")}}
                    onkeypress={move |e: KeyboardEvent| {if e.key() == "Enter" { HashHistory::new().push("/login")}}}>
                {"Already have an account?"}
            </div>
        </div>
    }
}