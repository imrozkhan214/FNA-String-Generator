import random
import streamlit as st
from itertools import product
from pyformlang.regular_expression import Regex
from pyformlang.finite_automaton import Symbol
import pygraphviz as pgv
from io import StringIO
from pyformlang.finite_automaton import State
from pyformlang.finite_automaton import DeterministicFiniteAutomaton

def rename_states(dfa):
    """
    Renames the states of a DFA to sequential letters starting from 'A'.
    """
    state_mapping = {state: State(chr(65 + idx)) for idx, state in enumerate(dfa.states)}
    renamed_dfa = dfa.__class__()
    renamed_dfa.add_start_state(state_mapping[dfa.start_state])
    for final_state in dfa.final_states:
        renamed_dfa.add_final_state(state_mapping[final_state])
    for state in dfa.states:
        for symbol in dfa.symbols:
            transitions = dfa.to_dict()
            if state in transitions and symbol in transitions[state]:
                next_state = transitions[state][symbol]
                renamed_dfa.add_transition(state_mapping[state], symbol, state_mapping[next_state])
    return renamed_dfa

def complete_dfa(dfa):
    """
    Checks if a DFA is complete, and if not, completes it by adding a dead state.
    """
    dead_state = State("Dead")
    alphabet = dfa.symbols
    transitions = dfa.to_dict()
    original_states = list(dfa.states)

    is_complete = all(
        symbol in transitions.get(state, {})
        for state in original_states
        for symbol in alphabet
    )

    if is_complete:
        return dfa

    for state in original_states:
        for symbol in alphabet:
            if symbol not in transitions.get(state, {}):
                dfa.add_transition(state, symbol, dead_state)
    for symbol in alphabet:
        dfa.add_transition(dead_state, symbol, dead_state)
    return dfa

def user_regex_to_dfa_and_cfg(regex_string):
    """
    Converts a regex string to a DFA and a CFG.
    """
    try:
        regex = Regex(regex_string)
        dfa = regex.to_epsilon_nfa().to_deterministic().minimize()
        dfa = complete_dfa(dfa)
        dfa = rename_states(dfa)

        cfg = regex.to_cfg().to_normal_form()

        return dfa, cfg
    except Exception as e:
        print(f"Error converting regex: {e}")
        return None, None

def visualize_dfa(dfa, layout='dot'):
    """
    Visualizes the DFA as a graph using pygraphviz.
    """
    graph = pgv.AGraph(strict=False, directed=True)
    graph.graph_attr.update(rankdir='LR', nodesep='1', ranksep='1.5', concentrate='false')

    for state in dfa.states:
        node_attrs = {
            "shape": "circle",
            "style": "filled",
            "fontcolor": "black",
            "width": "0.5",
        }
        if state == dfa.start_state and state in dfa.final_states:
            node_attrs.update({"shape": "doublecircle", "color": "lightgreen"})
        elif state == dfa.start_state:
            node_attrs.update({"color": "lightgreen"})
        elif state in dfa.final_states:
            node_attrs.update({"shape": "doublecircle", "color": "lightblue"})
        else:
            node_attrs.update({"color": "gray"})
        graph.add_node(state, **node_attrs)

    for state, transitions in dfa.to_dict().items():
        for symbol, next_state in transitions.items():
            graph.add_edge(state, next_state, label=str(symbol), fontsize='14', color='black', weight='5')

    graph.layout(prog=layout)
    return graph

def display_cfg(cfg):
    """
    Converts the CFG to a string representation with grouped productions.
    """
    grouped_productions = {}
    for production in cfg.productions:
        head = str(production.head)
        body = " ".join(str(symbol) for symbol in production.body)
        body = body.replace("Terminal(", "").replace(")", "")
        if head not in grouped_productions:
            grouped_productions[head] = []
        grouped_productions[head].append(body)

    result = []
    for head, bodies in grouped_productions.items():
        result.append(f"{head} -> {' | '.join(bodies)}")
    return "\n".join(result)

def generate_random_string(dfa, max_length):
    """
    Generates a random string accepted by the DFA up to max_length.
    """
    valid_strings = enumerate_strings(dfa, max_length)
    if not valid_strings:
        return None  # No valid strings exist
    return random.choice(valid_strings)  # Randomly pick one valid string


def enumerate_strings(dfa, max_length):
    """
    Enumerates all valid strings accepted by the DFA up to a given max string length.
    """
    valid_strings = []
    alphabet = list(dfa.symbols)  # Use DFA's symbols directly

    for length in range(1, max_length + 1):
        # Generate combinations of all possible strings of the given length
        for sequence in product(alphabet, repeat=length):
            # Convert tuple of symbols to string and check acceptance
            if dfa.accepts(sequence):
                valid_strings.append("".join(map(str, sequence)))

    return valid_strings


def main():
    st.title("Formal Language String Generator Tool")

    # Provide option to either generate DFA from regex or manually create automaton
    option = st.radio("Choose an option", ("Generate from Regex", "Make Own Automaton"))

    if option == "Generate from Regex":
        # Input for regular expression
        user_input_regex = st.text_input("Enter a regular expression (e.g., (0  1|0):)")
        
        if user_input_regex:
            # Convert the regex to DFA
            st.text("Converting regex to DFA...")
            dfa, cfg = user_regex_to_dfa_and_cfg(user_input_regex)
            
            if cfg:
                st.subheader("Generated CFG")
                st.text(display_cfg(cfg))

            if dfa:
                # Visualize DFA
                st.subheader("DFA Visualization")
                graph = visualize_dfa(dfa)
                img_path = "/tmp/dfa_graph.png"
                graph.layout(prog="dot")
                graph.draw(img_path)
                st.image(img_path)

                # Option for generating random strings
                st.subheader("Generate Random Strings")
                num_strings = st.number_input("Number of random strings to generate", min_value=1, value=5)
                max_length = st.number_input("Enter the maximum string length", min_value=1, value=5)

                if st.button("Generate"):
                    st.text("Generated Random Strings:")
                    for _ in range(num_strings):
                        rand_string = generate_random_string(dfa, max_length)
                        if rand_string:
                            st.text(rand_string)
                        else:
                            st.text("Failed to generate a valid string.")

                # Option for enumerating valid strings
                st.subheader("Enumerate Valid Strings")
                max_enum_length = st.number_input("Enter the maximum length to enumerate", min_value=1, value=5)

                if st.button("Enumerate"):
                    st.text("Enumerating strings...")
                    valid_strings = enumerate_strings(dfa, max_enum_length)
                    st.text(f"Total strings found: {len(valid_strings)}")
                    for string in valid_strings:
                        st.text(string)
                        
            


    elif option == "Make Own Automaton":
        # Manually create DFA

        start_state = st.text_input("Enter start state:")
        final_states = st.text_input("Enter final states (comma separated):").split(",")
        transitions_input = st.text_area("Enter transitions (format: state1,symbol,state2):")
        
        if start_state and final_states and transitions_input:
            dfa = DeterministicFiniteAutomaton()
            dfa.add_start_state(State(start_state))

            for final_state in final_states:
                dfa.add_final_state(State(final_state.strip()))

            for transition in transitions_input.splitlines():
                state1, symbol, state2 = transition.split(",")
                dfa.add_transition(State(state1.strip()), symbol.strip(), State(state2.strip()))

            # dfa = add_fal_state_self_loops(dfa)
            # dfa.minimize()
            
            dfa = complete_dfa(dfa)
            # Visualize DFA
            st.subheader("DFA Visualization")
            graph = visualize_dfa(dfa)
            img_path = "/tmp/dfa_manual_graph.png"
            graph.layout(prog="dot")
            graph.draw(img_path)
            st.image(img_path)
            
            # Option for generating random strings
            st.subheader("Generate Random Strings")
            num_strings = st.number_input("Number of random strings to generate", min_value=1, value=5)
            max_length = st.number_input("Enter the maximum string length", min_value=1, value=5)

            if st.button("Generate"):
                st.text("Generated Random Strings:")
                for _ in range(num_strings):
                    rand_string = generate_random_string(dfa, max_length)
                    if rand_string:
                        st.text(rand_string)
                    else:
                        st.text("Failed to generate a valid string.")

            # Option for enumerating valid strings
            st.subheader("Enumerate Valid Strings")
            max_enum_length = st.number_input("Enter the maximum length to enumerate", min_value=1, value=5)

            if st.button("Enumerate"):
                st.text("Enumerating strings...")
                valid_strings = enumerate_strings(dfa, max_enum_length)
                st.text(f"Total strings found: {len(valid_strings)}")
                for string in valid_strings:
                    st.text(string)

if __name__ == "__main__":
    main()