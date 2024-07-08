import streamlit as st
import random

def main():
    st.title("Alibaba Cave Zero-Knowledge Proof Demo")

    # Initialize session state
    if 'path_chosen' not in st.session_state:
        st.session_state['path_chosen'] = None
    if 'revealed_path' not in st.session_state:
        st.session_state['revealed_path'] = None
    if 'attempts' not in st.session_state:
        st.session_state['attempts'] = 0
    if 'successes' not in st.session_state:
        st.session_state['successes'] = 0

    st.header("Scenario")
    st.write("""
    Imagine a cave with two entrances, A and B, leading to a central door that requires a secret password to pass. 
    Jack (the prover) will enter through one entrance, and Bob (the verifier) will call out which entrance Jack should exit from. 
    If Jack knows the secret password, she can always exit through the correct entrance.
    """)

    st.header("Simulation")
    if st.session_state['path_chosen'] is None:
        if st.button("Jack Enters the Cave"):
            st.session_state['path_chosen'] = random.choice(['A', 'B'])
            st.write("Jack has entered the cave. Bob should now choose an exit.")

    if st.session_state['path_chosen'] is not None:
        st.write("Jack has entered through entrance", st.session_state['path_chosen'])
        path_choice = st.radio("Bob's Choice", ('A', 'B'))

        if st.button("Submit Choice"):
            st.session_state['revealed_path'] = path_choice
            st.session_state['attempts'] += 1
            if st.session_state['path_chosen'] == st.session_state['revealed_path']:
                st.session_state['successes'] += 1

            st.write(f"Bob chose entrance {st.session_state['revealed_path']}.")
            if st.session_state['path_chosen'] == st.session_state['revealed_path']:
                st.write("Jack successfully exited through the correct entrance!")
            else:
                st.write("Jack failed to exit through the correct entrance.")

            st.session_state['path_chosen'] = None
            st.session_state['revealed_path'] = None

    st.header("Results")
    st.write(f"Total Attempts: {st.session_state['attempts']}")
    st.write(f"Successful Exits: {st.session_state['successes']}")

if __name__ == "__main__":
    main()
