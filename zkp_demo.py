import streamlit as st
import random

def initialize_state():
    if 'path_chosen_knows' not in st.session_state:
        st.session_state['path_chosen_knows'] = None
    if 'revealed_path_knows' not in st.session_state:
        st.session_state['revealed_path_knows'] = None
    if 'attempts_knows' not in st.session_state:
        st.session_state['attempts_knows'] = 0
    if 'successes_knows' not in st.session_state:
        st.session_state['successes_knows'] = 0
    if 'path_chosen_not_knows' not in st.session_state:
        st.session_state['path_chosen_not_knows'] = None
    if 'revealed_path_not_knows' not in st.session_state:
        st.session_state['revealed_path_not_knows'] = None
    if 'attempts_not_knows' not in st.session_state:
        st.session_state['attempts_not_knows'] = 0
    if 'successes_not_knows' not in st.session_state:
        st.session_state['successes_not_knows'] = 0

def main():
    st.title("Alibaba Cave Zero-Knowledge Proof Demo")
    initialize_state()

    st.header("Scenario")
    st.write("""
    Imagine a cave with two entrances, A and B, leading to a central door that requires a secret password to pass. 
    Jack (the prover) will enter through one entrance, and Bob (the verifier) will call out which entrance Jack should exit from. 
    If Jack knows the secret password, she can always exit through the correct entrance.
    """)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Case 1: Jack knows the magic word")
        simulate_case('knows')

    with col2:
        st.subheader("Case 2: Jack does not know the magic word")
        simulate_case('not_knows')

    st.header("Results")
    with col1:
        st.write(f"Case 1 - Total Attempts: {st.session_state['attempts_knows']}")
        st.write(f"Case 1 - Successful Exits: {st.session_state['successes_knows']}")
    with col2:
        st.write(f"Case 2 - Total Attempts: {st.session_state['attempts_not_knows']}")
        st.write(f"Case 2 - Successful Exits: {st.session_state['successes_not_knows']}")

    # Reset button
    if st.button("Reset Simulation"):
        initialize_state()

def simulate_case(case):
    path_chosen = f'path_chosen_{case}'
    revealed_path = f'revealed_path_{case}'
    attempts = f'attempts_{case}'
    successes = f'successes_{case}'

    if st.session_state[path_chosen] is None:
        if st.button("Jack Enters the Cave", key=f'enter_{case}'):
            st.session_state[path_chosen] = random.choice(['A', 'B'])
            st.session_state['random_value'] = random.random()  # Generate a random value for Bob's choice

    if st.session_state[path_chosen] is not None:
        st.write(f"Jack has entered through entrance X")
        st.write(f"Random value for Bob's choice: {st.session_state['random_value']:.2f}")
        path_choice = st.radio("Bob's Choice", ('A', 'B'), key=f'choice_{case}')

        if st.button("Submit Choice", key=f'submit_{case}'):
            st.session_state[revealed_path] = path_choice
            st.session_state[attempts] += 1

            if case == 'knows':
                # success = st.session_state[path_chosen] == st.session_state[revealed_path]
                success = True
            else:
                # If Jack doesn't know the magic word, she has a 50% chance of exiting correctly
                success = st.session_state['random_value'] > 0.5

            if success:
                st.session_state[successes] += 1

            st.write(f"Bob chose entrance {st.session_state[revealed_path]}.")
            if success:
                st.write("Jack successfully exited through the correct entrance!")
            else:
                st.write("Jack failed to exit through the correct entrance.")

            st.session_state[path_chosen] = None
            st.session_state[revealed_path] = None

if __name__ == "__main__":
    main()
